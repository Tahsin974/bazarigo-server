const express = require("express");
const uuidv4 = require("uuid").v4;
const cors = require("cors");
const pool = require("./db");
const jwt = require("jsonwebtoken");
const path = require("path");
const fs = require("fs");
const sharp = require("sharp");
const sanitizeHtml = require("sanitize-html");

const crypto = require("crypto");
const bcrypt = require("bcrypt");
const passport = require("passport");
const cookieParser = require("cookie-parser");
const { default: axios } = require("axios");
const transporter = require("./mailer");
const ExcelJS = require("exceljs");
const multer = require("multer");
const cron = require("node-cron");
const createNotification = require("./createNotification");
const app = express();
const port = 3000;

const storage = multer.memoryStorage();
const upload = multer({ storage });
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

async function sendEmail(to, subject, html = null, userEmail = null) {
  try {
    const info = await transporter.sendMail({
      from: `"Bazarigo" <${process.env.EMAIL_USER}>`,
      to, // যাকে পাঠাতে চাও
      subject,
      html,
      replyTo: userEmail,
    });
  } catch (error) {
    console.error("Send Error:", error);
  }
}

async function generateUsername(email, pool, tableName = "users") {
  // Email থেকে username অংশ বের করা
  const namePart = email.split("@")[0];

  // Slugify
  const base =
    namePart
      .toLowerCase()
      .replace(/[^a-z]/g, "")
      .trim() || "user";

  let username;
  let tries = 0;

  do {
    if (tries++ > 50) {
      throw new Error("Unable to generate unique username after 50 attempts");
    }

    // 4-অঙ্কের random number
    const uniqueNum = Math.floor(1000 + Math.random() * 9000); // 1000–9999
    username = base + uniqueNum;

    // Database check
    const result = await pool.query(
      `SELECT 1 FROM ${tableName} WHERE user_name = $1 LIMIT 1`,
      [username],
    );

    if (result.rowCount === 0) break; // Unique username পেয়েছি
  } while (true);

  return username;
}

const cookieExtractor = (req) => {
  if (req && req.cookies && req.cookies.Token) {
    const raw = req.cookies.Token;

    // যদি cookie Bearer দিয়ে শুরু হয়
    if (raw.startsWith("Bearer ")) {
      return raw.split(" ")[1];
    }

    return raw;
  }
  return null;
};

const { Strategy: GoogleStrategy } = require("passport-google-oauth20");

const { Strategy: JwtStrategy } = require("passport-jwt");

/** Passport Google Strategy **/
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.URL}/auth/google/callback`,
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const email = profile.emails[0].value;
        const name = profile.displayName;

        // Generate a safe user_name

        const userName = await generateUsername(email, pool);

        // Check if user exists
        const result = await pool.query(
          "SELECT * FROM users WHERE email=$1 OR google_id=$2;",
          [email, profile.id],
        );

        let user;
        if (result.rows.length > 0) {
          const updatedQuery = `
        UPDATE users
        SET last_login = $1,
        role = $2

        WHERE id = $3
        RETURNING *;`;
          const updatedValues = [new Date(), "customer", result.rows[0].id];
          const updatedResult = await pool.query(updatedQuery, updatedValues);

          user = updatedResult.rows[0];
        } else {
          const id = uuidv4();
          const photoUrl =
            profile.photos && profile.photos.length > 0
              ? profile.photos[0].value
              : null;

          let savedPath = null;

          if (photoUrl) {
            const response = await axios.get(photoUrl, {
              responseType: "arraybuffer",
            });
            const buffer = Buffer.from(response.data, "binary");

            const safeName = userName.replace(/[^a-zA-Z0-9_-]/g, "_");
            const filename = `${safeName}.webp`;
            const uploadDir = path.join(
              __dirname,
              "uploads",
              "users",
              `${name}`,
            );
            if (!fs.existsSync(uploadDir))
              fs.mkdirSync(uploadDir, { recursive: true });

            await sharp(buffer)
              .resize(256, 256) // ইচ্ছেমতো সাইজ
              .webp({ lossless: true })
              .toFile(path.join(uploadDir, filename));

            savedPath = `/uploads/users/${name}/${filename}`;
          }

          const insertResult = await pool.query(
            `INSERT INTO users 
   (id,name,user_name,email,google_id,img,created_at,role) 
   VALUES ($1,$2,$3,$4,$5,$6,$7,$8) 
   RETURNING *;`,
            [
              id,
              name,
              userName,
              email,
              profile.id,
              savedPath,
              new Date(),
              "customer",
            ],
          );

          user = insertResult.rows[0];
        }

        cb(null, user);
      } catch (err) {
        cb(err, null);
      }
    },
  ),
);

/** Passport JWT Strategy **/
const opts = {
  jwtFromRequest: cookieExtractor, // Authorization: Bearer <token>
  secretOrKey: process.env.JWT_SECRET_KEY, // Strong secret from env
};

passport.use(
  new JwtStrategy(opts, async (jwt_payload, done) => {
    try {
      const { id, role } = jwt_payload;

      let table;
      if (role === "admin" || role === "super admin" || role === "moderator")
        table = "admins";
      else if (role === "seller") table = "sellers";
      else table = "users";

      const query = `SELECT * FROM ${table} WHERE id=$1;`;
      const result = await pool.query(query, [id]);

      if (result.rows.length === 0) return done(null, false);

      const user = { ...result.rows[0], role }; // role token থেকে attach করে দাও
      return done(null, user);
    } catch (err) {
      console.error("JWT Strategy error:", err);
      return done(err, false);
    }
  }),
);

const verifyAdmin = async (req, res, next) => {
  const user = req?.user;
  const isAdmin =
    user?.role === "admin" ||
    user?.role === "super admin" ||
    user?.role === "moderator";
  if (!isAdmin) {
    return res.status(403).send("forbidden access");
  }
  next();
};
const verifySeller = async (req, res, next) => {
  const user = req?.user;
  const isAdmin = user?.role === "seller";
  if (!isAdmin) {
    return res.status(403).send("forbidden access");
  }
  next();
};

app.use(
  cors({
    origin: [`${process.env.BASEURL}`],
    credentials: true,
  }),
);

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

app.use(passport.initialize());

app.use(cookieParser());

require("dotenv").config();

function generateId(name) {
  const uniqueId = uuidv4().replace(/-/g, "").slice(0, 12); // UUID থেকে ছোট আইডি
  const uniqueNumber = uuidv4()
    .replace(/[^0-9]/g, "") // only numbers
    .slice(0, 12);
  if (name === "OR") {
    return `${name}${uniqueNumber}`;
  }
  return `${name}${uniqueId.toUpperCase()}`;
}

// Duration parser
function parseDuration(duration) {
  const regex = /(\d+)([dhms])/g;
  let match;
  let ms = 0;
  while ((match = regex.exec(duration)) !== null) {
    const value = parseInt(match[1]);
    const unit = match[2];
    switch (unit) {
      case "d":
        ms += value * 24 * 60 * 60 * 1000;
        break;
      case "h":
        ms += value * 60 * 60 * 1000;
        break;
      case "m":
        ms += value * 60 * 1000;
        break;
      case "s":
        ms += value * 1000;
        break;
    }
  }
  return ms;
}
const UPLOADS_DIR = path.join(__dirname, "uploads");
const UNUSED_BACKUP_DIR = path.join(__dirname, "unused_backup");

// Ensure backup folder exists
if (!fs.existsSync(UNUSED_BACKUP_DIR)) {
  fs.mkdirSync(UNUSED_BACKUP_DIR, { recursive: true });
}

// Tables & columns to check
const IMAGE_COLUMNS = [
  { table: "banner", column: "image" },
  { table: "products", column: "images" },
  { table: "products", column: "thumbnail" },
  { table: "products", column: "variants_images" },

  { table: "sellers", column: "img" },
  { table: "sellers", column: "nid_front_file" },
  { table: "sellers", column: "nid_back_file" },
  { table: "sellers", column: "store_img" },
  { table: "users", column: "img" },
  { table: "products", column: "reviews" },
  { table: "return_requests", column: "images" },
  { table: "wishlist", column: "img" },
  { table: "admins", column: "profile_img" },
  { table: "admins", column: "store_img" },
  { table: "messages", column: "image_url" },
];

// Get referenced images from DB
async function getReferencedImages() {
  let referenced = new Set();

  for (const { table, column } of IMAGE_COLUMNS) {
    const res = await pool.query(`SELECT ${column} FROM ${table}`);
    res.rows.forEach((row) => {
      const val = row[column];
      if (!val) return;

      if (Array.isArray(val))
        val.forEach((v) => typeof v === "string" && referenced.add(v));
      else if (typeof val === "string") referenced.add(val);
      else if (Array.isArray(val?.reviews)) {
        val.reviews.forEach(
          (r) =>
            Array.isArray(r.images) &&
            r.images.forEach((img) => referenced.add(img)),
        );
      } else if (Array.isArray(val?.images))
        val.images.forEach((img) => referenced.add(img));
    });
  }

  return referenced;
}

// List all files in uploads folder recursively
function listFiles(dir) {
  let results = [];
  const list = fs.readdirSync(dir);
  list.forEach((file) => {
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);
    if (stat.isDirectory()) results = results.concat(listFiles(filePath));
    else results.push(filePath);
  });
  return results;
}

// Move unused images to backup folder
function moveUnusedImages(files) {
  files.forEach((file) => {
    const fileName = path.basename(file);
    const dest = path.join(UNUSED_BACKUP_DIR, fileName);

    // Handle same-name conflict
    let finalDest = dest;
    let counter = 1;
    while (fs.existsSync(finalDest)) {
      const ext = path.extname(fileName);
      const name = path.basename(fileName, ext);
      finalDest = path.join(UNUSED_BACKUP_DIR, `${name}_${counter}${ext}`);
      counter++;
    }

    fs.renameSync(file, finalDest);
    console.log(`Moved: ${file} → ${finalDest}`);
  });
}
function toInt(value, fallback = 0) {
  const n = parseInt(value);
  return isNaN(n) ? fallback : n;
}

async function run() {
  try {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const passwordRegex =
      /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_\-+=<>?])[A-Za-z\d!@#$%^&*()_\-+=<>?]{8,}$/;
    const CATEGORY_COMMISSION = {
      Electronics: 0.04, // 4%
      Fashion: 0.08, // 8%
      "Health & Beauty": 0.1, // 10%
      "Home & Living": 0.06, // 6%
      "Grocery & Food": 0.03, // 3%
      "Sports & Outdoors": 0.06, // 6%
      "Toys & Kids": 0.05, // 5%
      "Pet Supplies": 0.04, // 4%
    };

    // Database connection and operations would go here

    // --------------------cron jobs----------------------//

    // 03:00 AM every 3 days - unused images scan (not daily to save resources)
    cron.schedule("0 3 */3 * *", async () => {
      console.log("Starting unused image scan...");

      try {
        const referencedImages = await getReferencedImages();
        const allFiles = listFiles(UPLOADS_DIR);

        const unusedFiles = allFiles.filter((file) => {
          const relativePath =
            "/" + path.relative(__dirname, file).replace(/\\/g, "/");
          return !referencedImages.has(relativePath);
        });

        if (unusedFiles.length) {
          console.log(
            `Found ${unusedFiles.length} unused images. Moving to backup...`,
          );
          await sendEmail(
            process.env.SUPER_ADMIN,
            `System Maintenance Update: Image Backup Started
`,
            `
        <div style="font-family:Arial; max-width:600px; margin:auto; background:#fff; padding:20px; border-radius:10px;">
          <h2 style="color:#FF0055;">Image Backup Started</h2>
          <p>
            Unused images have been detected and are being moved to backup storage.
          </p>

          <p>
            <strong>Total images:</strong> ${unusedFiles.length}
          </p>

          <p style="font-size:13px; color:#666; margin-top:20px;">
            Cron Job executed on:<br/>
            ${new Date().toLocaleString()}
          </p>
        </div>
        `,
          );
          moveUnusedImages(unusedFiles);
        } else {
          console.log("No unused images found.");
        }
      } catch (err) {
        console.error("Error during scan:", err);
      }
    });

    // 04:00 AM Sunday - disable old products

    cron.schedule("0 4 * * 0", async () => {
      try {
        const updateQuery = `
      UPDATE products
      SET isnew = false
      WHERE createdat < NOW() - INTERVAL '15 days';
    `;

        await pool.query(updateQuery);
      } catch (error) {
        console.error("Cron error:", error.message);
      }
    });

    // 05:00 AM Sunday - Update Trending Products
    // "0 5 * * 0"

    cron.schedule("0 5 * * 0", async () => {
      console.log("Running trending products update...");
      try {
        // First: set trending = true for qualifying products
        const updateTrendingQuery = `
      UPDATE products p
      SET istrending = $1
      FROM (
          SELECT (prod->>'product_Id') AS product_id, SUM((prod->>'qty')::int) AS sold
          FROM orders o
          CROSS JOIN LATERAL jsonb_array_elements(o.order_items) AS item
          CROSS JOIN LATERAL jsonb_array_elements(item->'productinfo') AS prod
          WHERE o.order_date >= NOW() - INTERVAL '7 days'
          GROUP BY (prod->>'product_Id')
          HAVING SUM((prod->>'qty')::int) >= 10
      ) t
      WHERE p.id = t.product_id
        AND (
            p.rating >= 4
            OR COALESCE((
                SELECT AVG((r->>'rating')::numeric)
                FROM unnest(p.reviews) AS r
            ), 0) >= 4
        );
    `;

        const result1 = await pool.query(updateTrendingQuery, [true]);

        // Second: set trending = false for other products
        const updateNotTrendingQuery = `
      UPDATE products
      SET istrending = $1
      WHERE id NOT IN (
          SELECT (prod->>'product_Id')
          FROM orders o
          CROSS JOIN LATERAL jsonb_array_elements(o.order_items) AS item
          CROSS JOIN LATERAL jsonb_array_elements(item->'productinfo') AS prod
          WHERE o.order_date >= NOW() - INTERVAL '7 days'
          GROUP BY (prod->>'product_Id')
          HAVING SUM((prod->>'qty')::int) >= 10
      )
      OR NOT (
          rating >= 4
          OR COALESCE((
              SELECT AVG((r->>'rating')::numeric)
              FROM unnest(reviews) AS r
          ), 0) >= 4
      );
    `;

        await pool.query(updateNotTrendingQuery, [false]);

        // Send email only if trending products updated
        if (result1.rowCount > 0) {
          await sendEmail(
            process.env.SUPER_ADMIN,
            `Trending Products Update: System Sync Completed`,
            `
        <div style="font-family:Arial; max-width:600px; margin:auto; background:#fff; padding:20px; border-radius:10px;">
          <h2 style="color:#FF0055;">Trending Products Updated</h2>

          <p>
            The system has successfully analyzed recent user activity and updated the
            list of trending products.
          </p>

          <p>
            <strong>Total trending products identified:</strong> ${result1.rowCount}
          </p>

          <p>
            These products are now prioritized for visibility across the platform
            (homepage, search results, and promotional sections).
          </p>

          <p style="font-size:13px; color:#666; margin-top:20px;">
            Cron Job executed on:<br/>
            ${new Date().toLocaleString()}
          </p>
        </div>
        `,
          );
        }
      } catch (error) {
        console.log("Cron error:", error.message);
        console.error("Error updating trending products:", error);
      }
    });

    // ==========================
    // 06:30 AM daily - expired flash sale cleanup
    // ==========================

    // "30 6 * * *" => প্রতি দিন সকাল 6:30 টা

    cron.schedule("30 6 * * *", async () => {
      console.log("Running flash sale cleanup...");
      try {
        const now = Math.floor(Date.now() / 1000);

        // শেষ হওয়া ফ্ল্যাশ সেলগুলো
        const expiredResult = await pool.query(
          `SELECT id, sale_products FROM flashSaleProducts WHERE end_time <= $1`,
          [now],
        );

        if (expiredResult.rowCount === 0) return;

        const flashSales = expiredResult.rows;

        for (const sale of flashSales) {
          const flashProducts = sale.sale_products;

          for (const flashProd of flashProducts) {
            // main product
            const productRes = await pool.query(
              `SELECT * FROM products WHERE id = $1`,
              [flashProd.id],
            );
            if (productRes.rowCount === 0) continue;

            const mainProduct = productRes.rows[0];

            // ✅ Variant stock restore
            if (flashProd.variants?.length > 0) {
              for (const fv of flashProd.variants) {
                const stockToAdd = parseInt(fv.stock) || 0; // Ensure integer

                await pool.query(
                  `UPDATE product_variants SET stock = stock + $1::int WHERE id = $2`,
                  [stockToAdd, fv.id],
                );
              }

              // Update main product stock = sum of variant stock
              const totalStockRes = await pool.query(
                `SELECT COALESCE(SUM(stock),0) AS total_stock FROM product_variants WHERE product_id = $1`,
                [mainProduct.id],
              );
              mainProduct.stock = totalStockRes.rows[0].total_stock;
            } else {
              // Single product
              mainProduct.stock =
                (mainProduct.stock || 0) + (parseInt(flashProd.stock) || 0);
            }

            mainProduct.isflashsale = false;

            // main product update
            await pool.query(
              `UPDATE products SET stock=$1, isflashsale=false WHERE id=$2`,
              [mainProduct.stock, mainProduct.id],
            );

            // carts update
            await pool.query(
              `
        UPDATE carts
        SET productinfo = (
          SELECT jsonb_agg(
            CASE
              WHEN prod->>'product_Id' = $1
              THEN prod || jsonb_build_object(
                'isflashsale', false,
                'sale_price', $2::numeric,
                'regular_price', $3::numeric
              )
              ELSE prod
            END
          )
          FROM jsonb_array_elements(productinfo) prod
        )
        WHERE EXISTS (
          SELECT 1
          FROM jsonb_array_elements(productinfo) prod
          WHERE prod->>'product_Id' = $1
        )
        `,
              [
                mainProduct.id,
                mainProduct.sale_price || 0,
                mainProduct.regular_price || 0,
              ],
            );
          }
        }

        // ফ্ল্যাশ সেল ডিলিট
        const idsToDelete = flashSales.map((f) => f.id);
        await pool.query(
          `DELETE FROM flashSaleProducts WHERE id = ANY($1::int[])`,
          [idsToDelete],
        );
      } catch (err) {
        console.error("[FlashSale] Cron auto-delete error:", err);
      }
    });

    // ==========================
    // 12:00 AM daily - auto flash sale generation
    // ==========================

    // "0 0 * * *" => প্রতি দিন রাত 12 টা

    cron.schedule("0 0 * * *", async () => {
      try {
        const settingsRes = await pool.query(
          "SELECT is_auto_enabled FROM flash_sale_settings WHERE id=1",
        );
        if (!settingsRes.rows[0]?.is_auto_enabled) return;

        const now = Math.floor(Date.now() / 1000);

        // Check active flash sale
        const activeRes = await pool.query(
          `SELECT * FROM flashSaleProducts WHERE isactive = true AND end_time > $1 LIMIT 1`,
          [now],
        );
        if (activeRes.rows.length > 0) return;

        const productRes = await pool.query(`SELECT * FROM products`);
        const allProducts = productRes.rows;

        const candidates = allProducts.filter(
          (p) => (p.rating > 4.5 || p.isnew) && p.stock > 30,
        );
        if (!candidates.length) return;

        const autoSelected = candidates
          .sort(() => Math.random() - 0.5)
          .slice(0, 100);

        const minDiscount = 10;
        const maxDiscount = 30;

        let productPayload = [];
        let flashSalePayload = [];

        for (const prod of autoSelected) {
          const discount =
            Math.floor(Math.random() * (maxDiscount - minDiscount + 1)) +
            minDiscount;

          let updatedProd = { ...prod, isflashsale: true };
          let flashSaleProd = { ...prod, isflashsale: true, discount };

          // ✅ Variant logic using product_variants
          if (prod.variants?.length > 0) {
            const variantRes = await pool.query(
              `SELECT * FROM product_variants WHERE product_id=$1`,
              [prod.id],
            );
            const variants = variantRes.rows;

            let updatedVariants = [];
            let flashVariants = [];

            for (const v of variants) {
              const minStock = v.stock > 50 ? 40 : 2;
              const maxStock = v.stock > 50 ? 45 : 5;
              const flashStock =
                Math.floor(Math.random() * (maxStock - minStock + 1)) +
                minStock;
              const newStock = v.stock - flashStock;

              const salePrice = Math.round(
                (v.regular_price || 0) -
                  ((v.regular_price || 0) * discount) / 100,
              );

              flashVariants.push({
                ...v,
                stock: flashStock,
                sale_price: salePrice,
              });
              updatedVariants.push({ ...v, stock: newStock });
            }

            flashSaleProd.variants = flashVariants;
            flashSaleProd.stock = flashVariants.reduce(
              (sum, v) => sum + (v.stock || 0),
              0,
            );

            updatedProd.variants = updatedVariants;
            updatedProd.stock = updatedVariants.reduce(
              (sum, v) => sum + (v.stock || 0),
              0,
            );

            flashSalePayload.push(flashSaleProd);
            productPayload.push(updatedProd);
          } else {
            // Single product
            const minStock = prod.stock > 50 ? 45 : 3;
            const maxStock = prod.stock > 50 ? 50 : 5;
            const flashStock =
              Math.floor(Math.random() * (maxStock - minStock + 1)) + minStock;
            const newStock = prod.stock - flashStock;
            const salePrice = Math.round(
              (prod.regular_price || 0) -
                ((prod.regular_price || 0) * discount) / 100,
            );

            updatedProd.stock = newStock;
            flashSaleProd.stock = flashStock;
            flashSaleProd.sale_price = salePrice;

            flashSalePayload.push(flashSaleProd);
            productPayload.push(updatedProd);
          }
        }

        // Insert new flash sale
        const startTime = now;
        const endTime = now + 24 * 60 * 60;

        await pool.query(
          `INSERT INTO flashSaleProducts (isactive, start_time, end_time, sale_products)
       VALUES (true, $1, $2, $3)`,
          [startTime, endTime, JSON.stringify(flashSalePayload)],
        );

        // Update main product stocks
        for (const p of productPayload) {
          if (p.variants?.length > 0) {
            for (const v of p.variants) {
              await pool.query(
                `UPDATE product_variants SET stock=$1 WHERE id=$2`,
                [v.stock, v.id],
              );
            }

            const totalStockRes = await pool.query(
              `SELECT COALESCE(SUM(stock),0) AS total_stock FROM product_variants WHERE product_id=$1`,
              [p.id],
            );
            p.stock = totalStockRes.rows[0].total_stock;
          }

          await pool.query(
            `UPDATE products SET stock=$1, isflashsale=true WHERE id=$2`,
            [p.stock, p.id],
          );
        }
      } catch (err) {
        console.error("❌ Flash sale generation failed:", err.message);
      }
    });

    // 08:00 AM daily - cart notifications
    cron.schedule("0 8 * * *", async () => {
      try {
        const { rows: carts } = await pool.query(`
      SELECT 
  c.cart_id,
  u.id AS user_id,
  u.role AS user_role
FROM carts c
JOIN users u ON c.user_email = u.email
WHERE jsonb_array_length(c.productinfo) > 0
GROUP BY c.cart_id, u.id, u.role;

    `);

        if (carts.length === 0) {
          console.log("No carts found for notification.");
          return;
        }

        for (const user of carts) {
          await createNotification({
            userId: user.user_id,
            userRole: user.user_role,
            title: "Cart Reminder",
            message: "You have items in your cart. Don't forget to checkout!",
            type: "Cart",
            refId: user.cart_id, // user level notification, na je cart_id
            expiresAt: "7d",
          });
        }

        console.log("Notifications sent to unique users.");
      } catch (err) {
        console.error("Error sending cart notifications:", err);
      }
    });

    // 09:00 AM daily - delete expired notifications

    cron.schedule("0 9 * * *", async () => {
      try {
        const { rows } = await pool.query(
          `SELECT id, created_at, expires_at FROM notifications WHERE expires_at IS NOT NULL`,
        );
        const now = new Date();

        for (const row of rows) {
          const durationMs = parseDuration(row.expires_at);
          const expireTime = new Date(
            new Date(row.created_at).getTime() + durationMs,
          );

          if (now >= expireTime) {
            await pool.query(`DELETE FROM notifications WHERE id = $1`, [
              row.id,
            ]);
          }
        }
      } catch (err) {
        console.error("Error deleting expired notifications:", err);
      }
    });

    // --------------------Cron Jobs End-------------------//

    // Excel Download API Route

    app.get("/api/download-excel", async (req, res) => {
      try {
        const workbook = new ExcelJS.Workbook();

        // 1️⃣ Products sheet
        const productSheet = workbook.addWorksheet("Products");
        productSheet.columns = [
          { header: "productId", key: "productId", width: 30 },
          { header: "productName", key: "productName", width: 30 },
          { header: "brand", key: "brand", width: 20 },
          { header: "regular_price", key: "regular_price", width: 15 },
          { header: "sale_price", key: "sale_price", width: 15 },
          { header: "discount", key: "discount", width: 10 },
          { header: "stock", key: "stock", width: 10 },
          { header: "category", key: "category", width: 20 },
          { header: "subcategory", key: "subcategory", width: 20 },
          { header: "subcategory_item", key: "subcategory_item", width: 20 },
          { header: "description", key: "description", width: 30 },
          { header: "images", key: "images", width: 30 },
          { header: "thumbnail", key: "thumbnail", width: 30 },
        ];

        productSheet.getRow(1).eachCell((cell) => {
          cell.font = { bold: true };
          cell.alignment = { horizontal: "center", vertical: "middle" };
        });

        // --- Placeholder / instructions row ---
        productSheet.addRow({
          productId: "(enter product Id)",
          productName: "(enter product name)",
          brand: "(enter brand)",
          regular_price: "(enter regular price)",
          sale_price: "(enter sale price)",
          discount: "(enter discount)",
          stock: "(enter stock amount)",
          category: "(enter category)",
          subcategory: "(enter sub category)",
          subcategory_item: "(enter sub category item)",
          description: "(enter product description)",
          images: "(upload product image manually)",
          thumbnail: "(upload thumbnail image manually)",
        });
        productSheet.addRow({}); // Empty row for spacing

        const exampleRow = productSheet.addRow([
          "Example: Enter product info here",
        ]);
        productSheet.mergeCells(`A${exampleRow.number}:M${exampleRow.number}`);
        const mergedCell = productSheet.getCell(`A${exampleRow.number}`);
        mergedCell.font = { bold: true };
        mergedCell.alignment = {
          horizontal: "center",
          vertical: "middle",
          wrapText: true,
        };
        productSheet.getRow(exampleRow.number).height = 50;

        const productId = 1;

        // Sample product row
        productSheet.addRow({
          productId,
          productName: "Stylish Ladies Overcoat",
          brand: "Brand X",
          regular_price: 1000,
          sale_price: 850,
          discount: 15,
          stock: 50,
          category: "Fashion",
          subcategory: "Women’s Apparel",
          subcategory_item: "Dresses",
          description: "This is an example description of the product.",
          images: "image1.jpg,image2.jpg",
          thumbnail: "thumbnail.jpg",
        });

        // 2️⃣ Variants sheet
        const variantSheet = workbook.addWorksheet("Variants");
        variantSheet.columns = [
          { header: "productId", key: "productId", width: 30 },
          { header: "regular_price", key: "regular_price", width: 15 },
          { header: "sale_price", key: "sale_price", width: 15 },
          { header: "stock", key: "stock", width: 10 },
          { header: "attributes", key: "attributes", width: 50 },
        ];

        variantSheet.getRow(1).eachCell((cell) => {
          cell.font = { bold: true };
          cell.alignment = { horizontal: "center", vertical: "middle" };
        });

        // --- Placeholder / instructions row ---
        variantSheet.addRow({
          productId: "(enter product Id)",

          regular_price: "(enter Variant regular price)",
          sale_price: "(enter Variant sale price)",
          stock: "(enter Variant Stock Amount)",
          attributes: "(enter Variant Attributes)",
        });
        variantSheet.addRow({}); // Empty row for spacing

        const exampleRowVariant = variantSheet.addRow([
          "Example: Enter product variant here",
        ]);
        variantSheet.mergeCells(`A${exampleRow.number}:M${exampleRow.number}`);
        const mergedCellVariant = variantSheet.getCell(
          `A${exampleRowVariant.number}`,
        );
        mergedCellVariant.font = { bold: true };
        mergedCellVariant.alignment = {
          horizontal: "center",
          vertical: "middle",
          wrapText: true,
        };
        variantSheet.getRow(exampleRowVariant.number).height = 50;

        // Sample variants rows
        const sampleVariants = [
          {
            size: "XL",
            color: "Light Brown",
            material: "PU Leather",
            stock: 10,
            regular_price: 1200,
            sale_price: 0,
          },
          {
            size: "L",
            color: "Black",
            material: "PU Leather",
            stock: 10,
            regular_price: 1200,
            sale_price: 0,
          },
          {
            size: "M",
            color: "Maroon",
            material: "PU Leather",
            stock: 10,
            regular_price: 1200,
            sale_price: 0,
          },
        ];

        for (let variant of sampleVariants) {
          variantSheet.addRow({
            productId,
            regular_price: variant.regular_price,
            sale_price: variant.sale_price,
            stock: variant.stock,
            attributes: JSON.stringify({
              size: variant.size,
              color: variant.color,
              material: variant.material,
            }),
          });
        }

        // 3️⃣ Set headers for Excel download
        res.setHeader(
          "Content-Type",
          "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        );
        res.setHeader(
          "Content-Disposition",
          "attachment; filename=Products.xlsx",
        );

        await workbook.xlsx.write(res);
        res.end();
      } catch (err) {
        console.error(err);
        res.status(500).send("Excel ডাউনলোডে সমস্যা হয়েছে।");
      }
    });

    // -----------------Search Api Routes --------------//
    app.get("/search", async (req, res) => {
      const { query } = req.query;
      const search = `%${query}%`;

      // 1) Match products
      const productSearch = await pool.query(
        `SELECT DISTINCT ON (product_name)
       id, 
       product_name AS title,
       category,
       seller_store_name,
       subcategory, 
       subcategory_item,
       sale_price AS price, 
       thumbnail, 
       images,
       'product' AS type
FROM products
WHERE product_name ILIKE $1
ORDER BY product_name, createdAt DESC, id ASC;`,
        [search],
      );

      // 2) Match shops (sellers)
      const shopSearch = await pool.query(
        `SELECT DISTINCT ON (store_name) id, store_name AS title, store_img, 'shop' AS type
FROM sellers
WHERE store_name ILIKE $1 OR full_name ILIKE $1
ORDER BY store_name, id ASC;
`,
        [search],
      );

      res.json([...productSearch.rows, ...shopSearch.rows]);
    });
    // ---------------Search API Routes End-------------//

    // ------------ Banner API Routes-------------------//

    // POST: CREATE BANNER
    app.post("/banner", upload.single("image"), async (req, res) => {
      try {
        const { link } = req.body;
        const id = uuidv4();

        let bannerImg = null;
        const uploadDir = path.join(__dirname, "uploads", "banner");
        if (!fs.existsSync(uploadDir)) {
          fs.mkdirSync(uploadDir, { recursive: true });
        }

        if (req.file) {
          const filename = `banner_${uuidv4()}.webp`;
          const filepath = path.join(uploadDir, filename);

          // Convert and Save to .webp
          await sharp(req.file.buffer).webp({ quality: 80 }).toFile(filepath);

          // Save Path
          bannerImg = `/uploads/banner/${filename}`;
        }

        const query = `INSERT INTO banner (id, link, image) VALUES ($1, $2, $3);`;
        const values = [id, link, bannerImg];

        const result = await pool.query(query, values);

        res.status(200).json({
          createdCount: result.rowCount,
          message: "Banner Added Successfully!",
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // GET : RETURN ALL BANNER
    app.get(
      "/banner",

      async (req, res) => {
        try {
          const query = "SELECT * FROM banner;";
          const result = await pool.query(query);
          res.status(200).json({
            message: "Banner route is working!",
            banners: result.rows,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // DELETE : DELETE  BANNER BY ID
    app.delete("/banner/:id", async (req, res) => {
      try {
        const { id } = req.params;
        await pool.query("DELETE FROM banner WHERE id = $1", [id]);
        res.json({ message: "Banner deleted successfully" });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // ------------ Banner API Routes End -----------------//

    //------------ Products API Routes ----------------//

    //GET: Get Products API Route
    app.get(
      "/products",

      async (req, res) => {
        try {
          const query = `
WITH sold_data AS (
  SELECT
    pi->>'product_Id' AS product_id,
    SUM((pi->>'qty')::INT) AS sold
  FROM orders o
  LEFT JOIN LATERAL jsonb_array_elements(o.order_items) oi ON TRUE
  LEFT JOIN LATERAL jsonb_array_elements(oi->'productinfo') pi ON TRUE
  GROUP BY pi->>'product_Id'
),
variant_data AS (
  SELECT
    product_id,
    jsonb_agg(
      jsonb_strip_nulls(
        jsonb_build_object(
          'id', id,
          'regular_price', regular_price,
          'sale_price', sale_price,
          'stock', stock
        ) || attributes
      )
      ORDER BY created_at ASC
    ) AS variants
  FROM product_variants
  GROUP BY product_id
)
SELECT
  p.*,
  COALESCE(s.sold, 0) AS sold,
  COALESCE(v.variants, '[]') AS variants
FROM products p
LEFT JOIN sold_data s ON s.product_id = p.id
LEFT JOIN variant_data v ON v.product_id = p.id
ORDER BY sold DESC;
`;

          const result = await pool.query(query);
          res.status(200).json({
            message: "Products route is working!",
            products: result.rows,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    //GET: Get Single Product API Route

    app.get(
      "/products/:id",

      async (req, res) => {
        try {
          const productId = req.params.id;

          const query = `
WITH sold_data AS (
  SELECT
    pi->>'product_Id' AS product_id,
    SUM((pi->>'qty')::INT) AS sold
  FROM orders o
  LEFT JOIN LATERAL jsonb_array_elements(o.order_items) oi ON TRUE
  LEFT JOIN LATERAL jsonb_array_elements(oi->'productinfo') pi ON TRUE
  GROUP BY pi->>'product_Id'
),
variant_data AS (
  SELECT
    product_id,
    jsonb_agg(
      jsonb_strip_nulls(
        jsonb_build_object(
          'id', id,
          'regular_price', regular_price,
          'sale_price', sale_price,
          'stock', stock
        ) || attributes
      )
      ORDER BY created_at ASC
    ) AS variants
  FROM product_variants
  GROUP BY product_id
)
SELECT
  p.*,
  COALESCE(s.sold, 0) AS sold,
  COALESCE(v.variants, '[]') AS variants
FROM products p
LEFT JOIN sold_data s ON s.product_id = p.id
LEFT JOIN variant_data v ON v.product_id = p.id
WHERE p.id = $1;
`;

          const values = [productId];
          const result = await pool.query(query, values);

          res.status(200).json({
            message: `Single product route is working for ID: ${productId}`,
            product: result.rows[0],
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );
    // GET: Share Product API Route

    app.get("/share/product/:id", async (req, res) => {
      try {
        const productId = req.params.id;

        const BASE_URL = process.env.BASEURL;
        const BACKEND_URL = process.env.URL;

        const { rows } = await pool.query(
          `SELECT product_name, description, thumbnail
           FROM products WHERE id = $1`,
          [productId],
        );

        if (!rows.length) {
          return res.status(404).send("Product not found");
        }

        const product = rows[0];

        const stripHtml = (str = "") =>
          str
            .replace(/<[^>]*>/g, "")
            .replace(/\s+/g, " ")
            .trim();

        const title = product.product_name;
        const description =
          stripHtml(product.description).slice(0, 120) + "...";

        const imageUrl = product.thumbnail
          ? `${BACKEND_URL}${product.thumbnail}`
          : `${BASE_URL}/Bazarigo-Homepage-Thumbnail.jpg`;

        const ua = req.headers["user-agent"] || "";

        res.send(`<!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8" />
      <title>${title}</title>

      <link rel="canonical" href="${BASE_URL}/product/${productId}" />

      <meta property="og:type" content="product" />
      <meta property="og:title" content="${title}" />
      <meta property="og:description" content="${description}" />
      <meta property="og:image" content="${imageUrl}" />
      <meta property="og:image:width" content="1200" />
      <meta property="og:image:height" content="630" />
      <meta property="og:url" content="${BASE_URL}/product/${productId}" />

      <meta name="twitter:card" content="summary_large_image" />
    </head>

    <body>
      <p>Loading product…</p>
    </body>
    </html>`);
      } catch (err) {
        console.error(err);
        res.status(500).send("Server error");
      }
    });
    //GET: Get Products By SellerId API Route
    app.get(
      "/products/seller/:sellerId",

      async (req, res) => {
        try {
          const { sellerId } = req.params;

          const query = `
WITH sold_data AS (
  SELECT
    pi->>'product_Id' AS product_id,
    SUM((pi->>'qty')::INT) AS sold
  FROM orders o
  LEFT JOIN LATERAL jsonb_array_elements(o.order_items) oi ON TRUE
  LEFT JOIN LATERAL jsonb_array_elements(oi->'productinfo') pi ON TRUE
  GROUP BY pi->>'product_Id'
),
variant_data AS (
  SELECT
    product_id,
    jsonb_agg(
      jsonb_strip_nulls(
        jsonb_build_object(
          'id', id,
          'regular_price', regular_price,
          'sale_price', sale_price,
          'stock', stock
        ) || attributes
      )
      ORDER BY created_at ASC
    ) AS variants
  FROM product_variants
  GROUP BY product_id
)
SELECT
  p.*,
  COALESCE(s.sold, 0) AS sold,
  COALESCE(v.variants, '[]') AS variants
FROM products p
LEFT JOIN sold_data s ON s.product_id = p.id
LEFT JOIN variant_data v ON v.product_id = p.id
WHERE p.seller_id = $1
ORDER BY sold DESC;
`;

          const values = [sellerId];
          const result = await pool.query(query, values);

          res.status(200).json({
            message: `Seller product route is working for ID: ${sellerId}`,
            products: result.rows,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    //POST: Create Product API route

    app.post(
      "/products",
      passport.authenticate("jwt", { session: false }),
      upload.fields([
        { name: "thumbnail", maxCount: 1 },
        { name: "images", maxCount: 30 },
        { name: "variants_images", maxCount: 30 },
      ]),
      async (req, res) => {
        try {
          const {
            productName,
            regular_price,
            sale_price,
            discount,
            rating,
            isBestSeller,
            isHot,
            isNew,
            isTrending,
            isLimitedStock,
            isExclusive,
            isFlashSale,
            category,
            subcategory,
            subcategory_item,
            description,
            stock,
            brand,
            weight,
            variants,
          } = req.body;

          // Parse variants if string
          let parsedVariants = variants;
          if (typeof variants === "string") {
            try {
              parsedVariants = JSON.parse(variants);
            } catch (e) {
              return res.status(400).json({ message: "Invalid variants JSON" });
            }
          }

          // Seller info
          const user = req.user;
          let sellerId, sellerName, sellerStoreName, sellerRole;

          if (user.role === "seller" || user.role === "super admin") {
            sellerId = user.id;
            sellerName = user.full_name;
            sellerStoreName = user.store_name;
            sellerRole = user.role;
          } else {
            const bazarigo = await pool.query(
              "SELECT id, full_name, store_name, role FROM admins WHERE email='bazarigo.official@gmail.com' LIMIT 1;",
            );
            if (bazarigo.rows.length > 0) {
              sellerId = bazarigo.rows[0].id;
              sellerName = bazarigo.rows[0].full_name;
              sellerStoreName = bazarigo.rows[0].store_name;
              sellerRole = bazarigo.rows[0].role;
            }
          }

          // Sanitize description
          const sanitizedDescription = sanitizeHtml(description || "", {
            allowedTags: sanitizeHtml.defaults.allowedTags.concat([
              "img",
              "span",
              "div",
            ]),
            allowedAttributes: {
              ...sanitizeHtml.defaults.allowedAttributes,
              ul: ["class", "style"],
              ol: ["class", "style", "type"],
              li: ["class", "style", "data-list"],
              span: ["class", "style"],
              div: ["class", "style"],
              img: ["src", "alt", "width", "height"],
            },
          });

          const productId = uuidv4();

          // Upload directories
          const uploadDirs = {
            product: path.join(__dirname, "uploads", "products", "images"),
            thumbnail: path.join(
              __dirname,
              "uploads",
              "products",
              "thumbnails",
            ),
            variants: path.join(
              __dirname,
              "uploads",
              "products",
              "variants_images",
            ),
          };

          for (const dir of Object.values(uploadDirs)) {
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
          }

          /* ---------------- THUMBNAIL ---------------- */
          let thumbnailPath = null;
          if (req.files.thumbnail && req.files.thumbnail.length > 0) {
            const thumbFile = req.files.thumbnail[0];
            const thumbName = `${productName}-${productId}-thumb.webp`;
            const thumbPath = path.join(uploadDirs.thumbnail, thumbName);

            await sharp(thumbFile.buffer)
              .webp({ lossless: true })
              .toFile(thumbPath);
            thumbnailPath = `/uploads/products/thumbnails/${thumbName}`;
          }

          /* ---------------- MAIN PRODUCT IMAGES (UPDATED) ---------------- */
          const productImages = [];
          if (req.files.images) {
            for (const file of req.files.images) {
              const imageId = uuidv4(); // ✅ index বাদ
              const filename = `${productName}-${productId}-${imageId}.webp`;
              const filepath = path.join(uploadDirs.product, filename);

              await sharp(file.buffer)
                .webp({ lossless: true })
                .toFile(filepath);

              productImages.push(`/uploads/products/images/${filename}`);
            }
          }

          /* ---------------- VARIANT IMAGES (UNCHANGED) ---------------- */
          const variantImages = [];
          if (req.files.variants_images) {
            for (let i = 0; i < req.files.variants_images.length; i++) {
              const file = req.files.variants_images[i];
              const filename = `${productName}-${productId}-variant-${i}.webp`;
              const filepath = path.join(uploadDirs.variants, filename);

              await sharp(file.buffer)
                .webp({ lossless: true })
                .toFile(filepath);

              variantImages.push(
                `/uploads/products/variants_images/${filename}`,
              );
            }
          }

          /* ---------------- INSERT PRODUCT ---------------- */
          const productQuery = `
        INSERT INTO products (
          id, product_name, regular_price, sale_price, discount, rating,
          isBestSeller, isHot, isNew, isTrending, isLimitedStock, isExclusive, isFlashSale,
          category, subcategory, subcategory_item, description, stock, brand, weight,
          images, thumbnail,
          createdAt, updatedAt, seller_id, seller_name, seller_store_name, seller_role,
          variants_images
        ) VALUES (
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
          $14,$15,$16,$17,$18,$19,$20,$21,$22,
          NOW(),NOW(),$23,$24,$25,$26,$27
        ) RETURNING *;
      `;

          const productValues = [
            productId,
            productName,
            regular_price || 0,
            sale_price || 0,
            discount || 0,
            rating || 0,
            isBestSeller || false,
            isHot || false,
            isNew || true,
            isTrending || false,
            isLimitedStock || false,
            isExclusive || false,
            isFlashSale || false,
            category || null,
            subcategory || null,
            subcategory_item || null,
            sanitizedDescription || null,
            stock || 0,
            brand || null,
            weight || 1,
            productImages,
            thumbnailPath,
            sellerId || null,
            sellerName || null,
            sellerStoreName || "",
            sellerRole || "",
            variantImages.length > 0 ? variantImages : null,
          ];

          const result = await pool.query(productQuery, productValues);

          /* ---------------- INSERT VARIANTS ---------------- */
          if (Array.isArray(parsedVariants) && parsedVariants.length > 0) {
            for (const variant of parsedVariants) {
              const variantId = uuidv4();
              const {
                attributes,
                regular_price: vRegular,
                sale_price: vSale,
                stock: vStock,
              } = variant;

              await pool.query(
                `
            INSERT INTO product_variants (
              id, product_id, attributes, regular_price, sale_price, stock, created_at
            ) VALUES ($1,$2,$3,$4,$5,$6,NOW());
          `,
                [
                  variantId,
                  productId,
                  attributes || {},
                  toInt(vRegular, regular_price),
                  toInt(vSale, sale_price),
                  toInt(vStock, stock),
                ],
              );
            }
          }

          res.status(201).json({
            message: "Product and variants created successfully",
            productId,
            variantCount: parsedVariants ? parsedVariants.length : 0,
            createdCount: result.rowCount,
          });
        } catch (error) {
          console.error(error);
          res.status(500).json({ message: error.message });
        }
      },
    );

    //POST: Bulk Product Upload API Route

    app.post(
      "/products/bulk",
      passport.authenticate("jwt", { session: false }),
      upload.array("images"),
      async (req, res) => {
        try {
          const products = req.body;

          if (!Array.isArray(products) || products.length === 0) {
            return res.status(400).json({ message: "No products provided" });
          }

          const insertedProducts = [];
          const user = req.user;
          let sellerId, sellerName, sellerStoreName, sellerRole;

          for (const item of products) {
            item.id = uuidv4();

            // Parse variants if string
            let parsedVariants = item?.variants;
            if (typeof item.variants === "string") {
              try {
                parsedVariants = JSON.parse(item.variants);
              } catch (e) {
                return res
                  .status(400)
                  .json({ message: "Invalid variants JSON" });
              }
            }

            // Seller info
            if (user.role === "seller") {
              sellerId = user.id;
              sellerName = user.full_name;
              sellerStoreName = user.store_name;
              sellerRole = user.role;
            } else {
              const bazarigo = await pool.query(
                "SELECT id, full_name, store_name, role FROM admins WHERE email='bazarigo.official@gmail.com' LIMIT 1;",
              );
              if (bazarigo.rows.length > 0) {
                sellerId = bazarigo.rows[0].id;
                sellerName = bazarigo.rows[0].full_name;
                sellerStoreName = bazarigo.rows[0].store_name;
                sellerRole = bazarigo.rows[0].role;
              }
            }

            // Sanitize description
            const sanitizedDescription = sanitizeHtml(item.description || "", {
              allowedTags: sanitizeHtml.defaults.allowedTags.concat([
                "img",
                "span",
                "div",
              ]),
              allowedAttributes: {
                ...sanitizeHtml.defaults.allowedAttributes,
                ul: ["class", "style"],
                ol: ["class", "style", "type"],
                li: ["class", "style", "data-list"],
                span: ["class", "style"],
                div: ["class", "style"],
                img: ["src", "alt", "width", "height"],
              },
              allowedStyles: {
                "*": {
                  color: [/^.*$/],
                  "background-color": [/^.*$/],
                  "text-align": [/^left|right|center|justify$/],
                  "list-style-type": [/^.*$/],
                  "margin-left": [/^\d+(px|em|%)$/],
                  "padding-left": [/^\d+(px|em|%)$/],
                },
              },
            });

            // Process images
            const savedPaths = (
              await Promise.all(
                (item.images || []).map(async (imgStr) => {
                  if (!imgStr) return null;

                  if (imgStr.startsWith("data:image/")) {
                    const base64Data = imgStr.replace(
                      /^data:image\/\w+;base64,/,
                      "",
                    );
                    const buffer = Buffer.from(base64Data, "base64");
                    const safeName = (item.productName || "product").replace(
                      /\s+/g,
                      "_",
                    );
                    const filename = `${safeName}-${uuidv4()}.webp`;
                    const uploadDir = path.join(__dirname, "uploads");

                    if (!fs.existsSync(uploadDir))
                      fs.mkdirSync(uploadDir, { recursive: true });

                    const filepath = path.join(uploadDir, filename);
                    await sharp(buffer)
                      .webp({ lossless: true })
                      .toFile(filepath);

                    return `/uploads/${filename}`;
                  } else {
                    return imgStr.trim();
                  }
                }),
              )
            ).filter(Boolean);
            // Calculate main stock
            let mainStock = toInt(item.stock, 0); // default stock
            if (
              parsedVariants &&
              Array.isArray(parsedVariants) &&
              parsedVariants.length > 0
            ) {
              mainStock = parsedVariants.reduce(
                (sum, v) => sum + toInt(v.stock, 0),
                0,
              );
            }

            // Insert product
            const productQuery = `
          INSERT INTO products (
            id, product_name, regular_price, sale_price, discount, rating,
            isBestSeller, isHot, isNew, isTrending, isLimitedStock, isExclusive, isFlashSale,
            category, subcategory, description, stock, brand, weight, images, 
            createdAt, updatedAt, seller_id, seller_name, seller_store_name, reviews, seller_role, subcategory_item
          ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,NOW(),NOW(),$21,$22,$23,$24,$25,$26
          ) RETURNING *;
        `;

            const productValues = [
              item.id,
              item.productName || "Untitled",
              toInt(item.regular_price, 0),
              toInt(item.sale_price, 0),
              toInt(item.discount, 0),
              parseFloat(item.rating) || 0,
              item.isBestSeller || false,
              item.isHot || false,
              item.isNew !== undefined ? item.isNew : true,
              item.isTrending || false,
              item.isLimitedStock || false,
              item.isExclusive || false,
              item.isFlashSale || false,
              item.category || null,
              item.subcategory || null,

              sanitizedDescription,
              mainStock,
              item.brand || null,
              parseFloat(item.weight) || 1,
              savedPaths,
              sellerId || null,
              sellerName || null,
              sellerStoreName || "",
              [],
              sellerRole,
              item.subcategory_item || null,
            ];

            const result = await pool.query(productQuery, productValues);
            insertedProducts.push(result.rows[0]);

            // Insert variants if exist
            if (
              parsedVariants &&
              Array.isArray(parsedVariants) &&
              parsedVariants.length > 0
            ) {
              for (const variant of parsedVariants) {
                const variantId = uuidv4();
                const {
                  attributes,
                  regular_price: vRegular,
                  sale_price: vSale,
                  stock: vStock,
                } = variant;

                const variantQuery = `
              INSERT INTO product_variants (
                id, product_id, attributes, regular_price, sale_price, stock, created_at
              ) VALUES ($1,$2,$3,$4,$5,$6,NOW());
            `;

                await pool.query(variantQuery, [
                  variantId,
                  item.id,
                  attributes || {},
                  toInt(vRegular, 0),
                  toInt(vSale, 0),
                  toInt(vStock, 0),
                ]);
              }
            }
          }

          res.status(201).json({
            message: "Bulk products uploaded successfully",
            insertedCount: insertedProducts.length,
            insertedProducts,
          });
        } catch (error) {
          console.log("Bulk upload error:", error);
          res.status(500).json({ message: error.message });
        }
      },
    );

    // Helper function
    function toInt(value, defaultVal = 0) {
      const n = parseInt(value);
      return isNaN(n) ? defaultVal : n;
    }

    // PUT : Update Product By ID

    app.put(
      "/products/:id",
      passport.authenticate("jwt", { session: false }),
      upload.fields([
        { name: "thumbnail", maxCount: 1 },
        { name: "images", maxCount: 30 },
        { name: "variants_images", maxCount: 30 },
      ]), // multer middleware
      async (req, res) => {
        try {
          const productId = req.params.id;
          const {
            productName,
            regular_price,
            sale_price,
            discount,
            rating,
            isBestSeller,
            isHot,
            isNew,
            isTrending,
            isLimitedStock,
            isExclusive,
            isFlashSale,
            category,
            subcategory,
            subcategory_item,
            description,
            stock,
            brand,
            variants,
            existingThumbnail,
          } = req.body;
          // Insert variants with separate images
          let parsedVariants = variants;

          // FormData থেকে আসলে variants string হয়
          if (typeof variants === "string") {
            try {
              parsedVariants = JSON.parse(variants);
            } catch (e) {
              return res.status(400).json({ message: "Invalid variants JSON" });
            }
          }
          const normalizeVariant = (v) => {
            if (v.attributes) return v;
            const { id, tempId, regular_price, sale_price, stock, ...rest } = v;
            return {
              id,
              tempId,
              attributes: rest,
              regular_price: regular_price || 0,
              sale_price: sale_price || 0,
              stock: stock || 0,
            };
          };

          parsedVariants = parsedVariants.map(normalizeVariant);

          const uploadDirs = {
            image: path.join(__dirname, "uploads", "products", "images"),
            video: path.join(__dirname, "uploads", "products", "videos"),
            thumbnail: path.join(
              __dirname,
              "uploads",
              "products",
              "thumbnails",
            ),
            variants: path.join(__dirname, "uploads/products/variants_images"),
          };

          // create directories if not exist
          for (const dir of Object.values(uploadDirs)) {
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
          }
          // previous paths নেওয়া
          const existingPaths = req.body.existingPaths
            ? JSON.parse(req.body.existingPaths)
            : [];
          const oldVariantImages = req.body.existingVariantPaths
            ? JSON.parse(req.body.existingVariantPaths)
            : [];

          // নতুন upload হওয়া ফাইলগুলো process
          const newPaths = await Promise.all(
            (req.files.images || []).map(async (file, index) => {
              const mime = file.mimetype;

              if (mime.startsWith("image")) {
                const filename = `${productId}-${Date.now()}-${index}.webp`;
                const filepath = path.join(uploadDirs.image, filename);

                await sharp(file.buffer)
                  .webp({ lossless: true })
                  .toFile(filepath);

                return `/uploads/products/images/${filename}`;
              }

              if (mime.startsWith("video")) {
                const ext = mime.split("/")[1];
                const filename = `${productId}-${Date.now()}-${index}.${ext}`;
                const filepath = path.join(uploadDirs.video, filename);

                await fs.promises.writeFile(filepath, file.buffer);

                return `/uploads/products/videos/${filename}`;
              }

              return null;
            }),
          );
          /* -------------------- VARIANT IMAGES -------------------- */
          const newVariantPaths = await Promise.all(
            (req.files.variants_images || []).map(async (file, index) => {
              if (!file.mimetype.startsWith("image/")) return null;

              const filename = `${productId}-variant-${Date.now()}-${index}.webp`;
              const filepath = path.join(uploadDirs.variants, filename);

              await sharp(file.buffer)
                .resize(800)
                .webp({ quality: 80 })
                .toFile(filepath);

              return `/uploads/products/variants_images/${filename}`;
            }),
          );

          // merge old + new
          const savedPaths = [...newPaths, ...existingPaths].filter(Boolean);
          const savedVariantPaths = [
            ...oldVariantImages,
            ...newVariantPaths,
          ].filter(Boolean);

          // ✅ thumbnail handling (FIXED)
          let thumbnailPath = existingThumbnail || null;

          if (req.files.thumbnail && req.files.thumbnail.length > 0) {
            const thumbFile = req.files.thumbnail[0];
            const thumbName = `${productId}-thumb-${Date.now()}.webp`;
            const thumbPath = path.join(uploadDirs.thumbnail, thumbName);

            await sharp(thumbFile.buffer)
              .webp({ lossless: true })
              .toFile(thumbPath);

            thumbnailPath = `/uploads/products/thumbnails/${thumbName}`;

            // optional: delete old thumbnail
            if (existingThumbnail) {
              const oldPath = path.join(__dirname, existingThumbnail);
              if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
            }
          }

          const sanitizedDescription = sanitizeHtml(description, {
            allowedTags: sanitizeHtml.defaults.allowedTags.concat([
              "img",
              "span",
              "div",
            ]),

            allowedAttributes: {
              ...sanitizeHtml.defaults.allowedAttributes,

              // 👇 VERY IMPORTANT for Quill
              ul: ["class", "style"],
              ol: ["class", "style", "type"],
              li: ["class", "style", "data-list"],

              span: ["class", "style"],
              div: ["class", "style"],

              img: ["src", "alt", "width", "height"],
            },

            // 👇 allow inline styles (safe list)
            allowedStyles: {
              "*": {
                color: [/^.*$/],
                "background-color": [/^.*$/],
                "text-align": [/^left|right|center|justify$/],
                "list-style-type": [/^.*$/],
                "margin-left": [/^\d+(px|em|%)$/],
                "padding-left": [/^\d+(px|em|%)$/],
              },
            },
          });

          const query = `
            UPDATE products SET
              product_name=$1, regular_price=$2, sale_price=$3, discount=$4, rating=$5,
              isBestSeller=$6, isHot=$7, isNew=$8, isTrending=$9, isLimitedStock=$10, isExclusive=$11, isFlashSale=$12,
              category=$13, subcategory=$14, description=$15, stock=$16, brand=$17, images=$18,
              subcategory_item=$19,
              thumbnail=$20,
              updatedAt=NOW(),
                variants_images=$21

            WHERE id=$22;
          `;
          const values = [
            productName,
            regular_price,
            sale_price,
            discount,
            rating,
            isBestSeller,
            isHot,
            isNew,
            isTrending,
            isLimitedStock,
            isExclusive,
            isFlashSale,
            category,
            subcategory,
            sanitizedDescription,
            stock,
            brand,
            savedPaths,

            subcategory_item,
            thumbnailPath, // new thumbnail
            savedVariantPaths.length > 0 ? savedVariantPaths : null,
            productId,
          ];

          const result = await pool.query(query, values);
          // Fetch existing variant IDs
          const existingVariantsRes = await pool.query(
            "SELECT id FROM product_variants WHERE product_id=$1",
            [productId],
          );
          const existingIds = existingVariantsRes.rows.map((v) => v.id);

          // Determine insert/update/delete
          const variantsToInsert = [];
          const variantsToUpdate = [];
          const idsToKeep = [];

          parsedVariants.forEach((v) => {
            if (v.id && existingIds.includes(v.id)) {
              variantsToUpdate.push(v);
              idsToKeep.push(v.id);
            } else {
              variantsToInsert.push(v);
            }
          });

          const idsToDelete = existingIds.filter(
            (id) => !idsToKeep.includes(id),
          );
          if (idsToDelete.length > 0) {
            await pool.query(
              `DELETE FROM product_variants WHERE id = ANY($1::varchar[])`,
              [idsToDelete],
            );
          }

          // Update existing variants
          for (const v of variantsToUpdate) {
            await pool.query(
              `UPDATE product_variants SET attributes=$1, regular_price=$2, sale_price=$3, stock=$4 WHERE id=$5`,
              [
                v.attributes || {},
                toInt(v.regular_price),
                toInt(v.sale_price),
                toInt(v.stock),
                v.id,
              ],
            );
          }

          // Insert new variants
          for (const v of variantsToInsert) {
            const variantId = uuidv4();
            await pool.query(
              `INSERT INTO product_variants (id, product_id, attributes, regular_price, sale_price, stock, created_at)
           VALUES ($1,$2,$3,$4,$5,$6,NOW())`,
              [
                variantId,
                productId,
                v.attributes || {},
                toInt(v.regular_price),
                toInt(v.sale_price),
                toInt(v.stock),
              ],
            );
          }

          res.status(200).json({
            message: `Product updated successfully for ID: ${productId}`,
            updatedCount: result.rowCount,
          });
        } catch (err) {
          console.error(err);
          res.status(500).json({ message: err.message });
        }
      },
    );

    // PUT: Add a single review to a product

    app.put(
      "/products/:id/reviews",
      upload.array("images"), // "images" হলো frontend FormData field name
      async (req, res) => {
        try {
          const productId = req.params.id;
          const { name, comment, rating, date, email } = req.body;

          if (!name || !comment) {
            return res.status(400).json({ message: "Missing required fields" });
          }

          // Multer files থেকে WebP save & path collect

          const uploadDir = path.join(
            __dirname,
            "uploads",
            "products",
            "reviews",
          );

          // Ensure folder exists
          if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
          }

          const savedPaths = await Promise.all(
            (req.files || []).map(async (file, i) => {
              try {
                const filename = `review-${Date.now()}-${i}.webp`;
                const filepath = path.join(uploadDir, filename);

                await sharp(file.buffer)
                  .webp({ lossless: true })
                  .toFile(filepath);

                return `/uploads/products/reviews/${filename}`;
              } catch (err) {
                console.error(`Failed to save image ${i}:`, err.message);
                return null;
              }
            }),
          );

          const finalSavedPaths = savedPaths.filter((p) => p !== null);

          const newReview = {
            id: uuidv4(),
            name,
            email,
            comment,
            rating: rating ? Number(rating) : 0,
            images: finalSavedPaths,
            date: date || new Date(),
          };

          // Existing reviews fetch
          const selectQuery = `SELECT reviews FROM products WHERE id = $1`;
          const selectResult = await pool.query(selectQuery, [productId]);

          if (selectResult.rowCount === 0) {
            return res.status(404).json({ message: "Product not found" });
          }

          const existingReviews = selectResult.rows[0].reviews || [];
          const updatedReviews = [...existingReviews, newReview];

          const updateQuery = `
        UPDATE products
        SET reviews = $1
        WHERE id = $2
        RETURNING *;
      `;
          const updateResult = await pool.query(updateQuery, [
            updatedReviews,
            productId,
          ]);

          res.status(200).json({
            message: "Review added successfully",
            updatedCount: updateResult.rowCount,
          });
        } catch (error) {
          console.error(error);
          res.status(500).json({ message: error.message });
        }
      },
    );

    // PUT: Add a single question to a product

    app.put(
      "/products/add-question/:id",
      passport.authenticate("jwt", { session: false }),
      async (req, res) => {
        try {
          const { id } = req.params;
          const newQuestion = req.body; // already JSON

          // 1) Existing questions নাও
          const selectQuery = `SELECT questions FROM products WHERE id = $1`;
          const selectResult = await pool.query(selectQuery, [id]);

          if (selectResult.rowCount === 0) {
            return res.status(404).json({ message: "Product not found" });
          }

          // 2) যদি আগে কোন প্রশ্ন না থাকে, empty array fallback
          const existingQuestions = selectResult.rows[0].questions || [];

          // 3) নতুন প্রশ্ন add করো
          const updatedQuestions = [newQuestion, ...existingQuestions]; // recent first

          // 4) Database update করো
          const query = `
      UPDATE products
      SET questions = $1
      WHERE id = $2
      RETURNING questions
    `;
          const result = await pool.query(query, [updatedQuestions, id]);

          // 6) admin গুলোর কাছে notification পাঠাও
          const sellerResult = await pool.query(
            "SELECT seller_id,seller_role FROM products WHERE id=$1",
            [id],
          );

          await createNotification({
            userId: sellerResult.rows[0].seller_id,
            userRole: sellerResult.rows[0].seller_role,
            title: "Customer Question Received",
            message: `A new question from ${
              req.user?.name ? req.user.name : req.user.full_name
            } was asked for product "${newQuestion.productName}": "${
              newQuestion.question
            }"`,
            type: "new_question",
            refId: id,
            expiresAt: "15d",
          });

          res.json({
            success: true,
            updatedQuestions: result.rows[0].questions,
          });
        } catch (error) {
          res.status(500).json({ success: false, error: error.message });
        }
      },
    );

    // PUT: Add reply of a single question to a product

    app.put(
      "/products/reply-question/:id",
      passport.authenticate("jwt", { session: false }),
      async (req, res) => {
        try {
          const { id } = req.params; // product ID
          const { q_id, answer, replyDate } = req.body; // question ID এবং answer

          // 1) Check if product exists
          const selectQuery = `SELECT questions FROM products WHERE id = $1`;
          const selectResult = await pool.query(selectQuery, [id]);

          if (selectResult.rowCount === 0) {
            return res.status(404).json({ message: "Product not found" });
          }

          const questions = selectResult.rows[0].questions || [];

          // 2) Find the question to reply
          const questionToReply = questions.find((q) => q.id === q_id);
          if (!questionToReply) {
            return res.status(404).json({ message: "Question not found" });
          }

          // 3) Update the specific question
          let updatedQuestions;
          if (req.user.role === "seller") {
            updatedQuestions = questions.map((q) =>
              q.id === q_id
                ? { ...q, answer, answeredBySeller: true, replyDate }
                : q,
            );
          } else {
            updatedQuestions = questions.map((q) =>
              q.id === q_id
                ? { ...q, answer, answeredByAdmin: true, replyDate }
                : q,
            );
          }

          // 4) Save back to database
          const updateQuery = `
      UPDATE products
      SET questions = $1
      WHERE id = $2
      RETURNING questions
    `;
          const updateResult = await pool.query(updateQuery, [
            updatedQuestions,
            id,
          ]);

          // 5) Send notification to the customer
          await createNotification({
            userId: questionToReply.customerId, // customer ID
            userRole: questionToReply.customerRole,
            title: "Your question has been answered",
            message: `Seller replied "${answer}" to your question for product "${questionToReply.productName}": "${questionToReply.question}"
          
          `,
            type: "question_answer",
            refId: id,
            expiresAt: "15d",
          });

          res.json({
            success: true,
            updatedQuestions: updateResult.rows[0].questions,
          });
        } catch (error) {
          console.error(error);
          res.status(500).json({ success: false, error: error.message });
        }
      },
    );

    // DELETE Review by ID
    app.delete(
      "/products/:productId/reviews/:reviewId",
      passport.authenticate("jwt", { session: false }),
      async (req, res) => {
        try {
          const { productId, reviewId } = req.params;

          const query = `
        UPDATE products
        SET reviews = ARRAY(
          SELECT r
          FROM unnest(reviews) AS r
          WHERE r->>'id' <> $1
        )
        WHERE id = $2
        RETURNING reviews;
      `;

          const result = await pool.query(query, [reviewId, productId]);

          if (result.rows.length === 0) {
            return res
              .status(404)
              .json({ success: false, message: "Product or review not found" });
          }

          res.json({ success: true, reviews: result.rows[0].reviews });
        } catch (error) {
          console.error(error);
          res.status(500).json({ success: false, error: error.message });
        }
      },
    );

    //DELETE: BULK Delete  Product API Route
    app.delete(
      "/products/bulk-delete",
      passport.authenticate("jwt", { session: false }),
      async (req, res) => {
        try {
          const { ids } = req.body; // expects array of IDs
          const user = req.user;
          if (!ids || !ids.length)
            return res.status(400).json({ message: "No IDs provided" });
          let deletableIds = ids;
          // Moderator restriction
          if (user.role === "moderator") {
            const { rows } = await pool.query(
              `SELECT id FROM products WHERE id = ANY($1) AND "canDeleteByModerator" = true`,
              [ids],
            );
            deletableIds = rows.map((r) => r.id);

            if (deletableIds.length === 0) {
              return res.status(403).json({
                message: "You are not allowed to delete selected products",
              });
            }
          }

          const query = `DELETE FROM products WHERE id = ANY($1)`;
          const result = await pool.query(query, [ids]);

          res.status(200).json({ deletedCount: result.rowCount });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    //DELETE: Delete Single Product API Route
    app.delete(
      "/products/:id",
      passport.authenticate("jwt", { session: false }),
      async (req, res) => {
        try {
          const user = req.user;
          const productId = req.params.id;

          // Moderator হলে চেক করা হবে
          if (user.role === "moderator") {
            const { rows } = await pool.query(
              'SELECT id FROM products WHERE id = $1 AND "canDeleteByModerator" = true',
              [productId],
            );

            if (rows.length === 0) {
              return res.status(403).json({
                message: "You are not allowed to delete this product",
              });
            }
          }
          const query = "DELETE FROM products WHERE id =$1;";
          const values = [productId];
          const result = await pool.query(query, values);
          res.status(200).json({
            message: `Delete Single product route is working for ID: ${productId}`,
            deletedCount: result.rowCount,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    //GET: Just Arrived API Route
    app.get("/just-arrived", async (req, res) => {
      try {
        const query = `
  SELECT 
    p.id,
    p.product_name,
    p.regular_price,
    p.sale_price,
    p.discount,
    p.rating,
    p.category,
    p.isbestseller,
    p.isnew,
    p.images,
    p.thumbnail,
    p.reviews,
    COALESCE(SUM((pi->>'qty')::INT), 0) AS sold
  FROM products p
  LEFT JOIN orders o
    ON TRUE
  LEFT JOIN LATERAL jsonb_array_elements(o.order_items) AS oi
    ON TRUE
  LEFT JOIN LATERAL jsonb_array_elements(oi->'productinfo') AS pi
    ON pi->>'product_Id' = p.id
  WHERE p.isnew = $1 
    AND p.createdat >= NOW() - INTERVAL '15 days'
  GROUP BY p.id
  ORDER BY p.createdat DESC
  LIMIT 20;
`;

        const result = await pool.query(query, [true]);

        res.status(200).json({
          message: "Just Arrived route is working!",
          products: result.rows,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    //GET: Trending Products API Route
    app.get("/trending-products", async (req, res) => {
      try {
        const query = `
                 SELECT
            p.id,
            p.product_name,
            p.regular_price,
            p.sale_price,
            p.discount,
            p.rating,
            p.images,
            p.thumbnail,
            p.isBestSeller,
            p.isNew,
            p.reviews,
            SUM((prod->>'qty')::int) AS sold
        FROM products p
        JOIN orders o
            ON o.order_date >= NOW() - INTERVAL '7 days'
        CROSS JOIN LATERAL jsonb_array_elements(o.order_items) AS item
        CROSS JOIN LATERAL jsonb_array_elements(item->'productinfo') AS prod
        WHERE (prod->>'product_Id') = p.id
          AND p.istrending = $1
        GROUP BY p.id
        HAVING SUM((prod->>'qty')::int) >= 5
           AND (
               p.rating >= 4
               OR COALESCE((
                   SELECT AVG((r->>'rating')::numeric)
                   FROM unnest(p.reviews) AS r
               ), 0) >= 4
           )
        ORDER BY sold DESC
        LIMIT 20;

                `;

        const result = await pool.query(query, [true]);

        return res.status(200).json({
          message: "Trending Products route is working!",

          products: result.rows,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    //GET: Electronics API Route
    app.get("/electronics", async (req, res) => {
      try {
        const query = `
  SELECT 
    p.id,
    p.product_name,
    p.regular_price,
    p.sale_price,
    p.discount,
    p.rating,
    p.category,
    p.isbestseller,
    p.isnew,
    p.images,
    p.thumbnail,
    p.reviews,
    COALESCE(SUM((pi->>'qty')::INT), 0) AS sold
  FROM products p
  LEFT JOIN orders o
    ON TRUE
  LEFT JOIN LATERAL jsonb_array_elements(o.order_items) AS oi
    ON TRUE
  LEFT JOIN LATERAL jsonb_array_elements(oi->'productinfo') AS pi
    ON pi->>'product_Id' = p.id
  WHERE p.isnew = $1 
    AND p.category = 'Electronics'
  GROUP BY p.id
 ORDER BY RANDOM()
  LIMIT 4;
`;

        const result = await pool.query(query, [false]);

        res.status(200).json({
          message: "Electronics route is working!",
          products: result.rows,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
    //GET: Fashion API Route
    app.get("/fashion", async (req, res) => {
      try {
        const query = `
  SELECT 
    p.id,
    p.product_name,
    p.regular_price,
    p.sale_price,
    p.discount,
    p.rating,
    p.category,
    p.isbestseller,
    p.isnew,
    p.images,
    p.thumbnail,
    p.reviews,
    COALESCE(SUM((pi->>'qty')::INT), 0) AS sold
  FROM products p
  LEFT JOIN orders o
    ON TRUE
  LEFT JOIN LATERAL jsonb_array_elements(o.order_items) AS oi
    ON TRUE
  LEFT JOIN LATERAL jsonb_array_elements(oi->'productinfo') AS pi
    ON pi->>'product_Id' = p.id
  WHERE p.isnew = $1 
    AND p.category = 'Fashion'
  GROUP BY p.id
 ORDER BY RANDOM()
  LIMIT 4;
`;

        const result = await pool.query(query, [false]);

        res.status(200).json({
          message: "Fashion route is working!",
          products: result.rows,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
    //GET: Health & Beauty API Route
    app.get("/health-beauty", async (req, res) => {
      try {
        const query = `
  SELECT 
    p.id,
    p.product_name,
    p.regular_price,
    p.sale_price,
    p.discount,
    p.rating,
    p.category,
    p.isbestseller,
    p.isnew,
    p.images,
    p.thumbnail,
    p.reviews,
    COALESCE(SUM((pi->>'qty')::INT), 0) AS sold
  FROM products p
  LEFT JOIN orders o
    ON TRUE
  LEFT JOIN LATERAL jsonb_array_elements(o.order_items) AS oi
    ON TRUE
  LEFT JOIN LATERAL jsonb_array_elements(oi->'productinfo') AS pi
    ON pi->>'product_Id' = p.id
  WHERE p.isnew = $1 
    AND p.category = 'Health & Beauty'
  GROUP BY p.id
 ORDER BY RANDOM()
  LIMIT 4;
`;

        const result = await pool.query(query, [false]);

        res.status(200).json({
          message: "Health & Beauty route is working!",
          products: result.rows,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
    //GET: Home & Living API Route
    app.get("/home-living", async (req, res) => {
      try {
        const query = `
  SELECT 
    p.id,
    p.product_name,
    p.regular_price,
    p.sale_price,
    p.discount,
    p.rating,
    p.category,
    p.isbestseller,
    p.isnew,
    p.images,
    p.thumbnail,
    p.reviews,
    COALESCE(SUM((pi->>'qty')::INT), 0) AS sold
  FROM products p
  LEFT JOIN orders o
    ON TRUE
  LEFT JOIN LATERAL jsonb_array_elements(o.order_items) AS oi
    ON TRUE
  LEFT JOIN LATERAL jsonb_array_elements(oi->'productinfo') AS pi
    ON pi->>'product_Id' = p.id
  WHERE p.isnew = $1 
    AND p.category = 'Home & Living'
  GROUP BY p.id
 ORDER BY RANDOM()
  LIMIT 4;
`;

        const result = await pool.query(query, [false]);

        res.status(200).json({
          message: "Home & Living route is working!",
          products: result.rows,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
    //GET: Sports & Outdoors API Route
    app.get("/sports-outdoors", async (req, res) => {
      try {
        const query = `
  SELECT 
    p.id,
    p.product_name,
    p.regular_price,
    p.sale_price,
    p.discount,
    p.rating,
    p.category,
    p.isbestseller,
    p.isnew,
    p.images,
    p.thumbnail,
    p.reviews,
    COALESCE(SUM((pi->>'qty')::INT), 0) AS sold
  FROM products p
  LEFT JOIN orders o
    ON TRUE
  LEFT JOIN LATERAL jsonb_array_elements(o.order_items) AS oi
    ON TRUE
  LEFT JOIN LATERAL jsonb_array_elements(oi->'productinfo') AS pi
    ON pi->>'product_Id' = p.id
  WHERE p.isnew = $1 
    AND p.category = 'Sports & Outdoors'
  GROUP BY p.id
 ORDER BY RANDOM()
  LIMIT 4;
`;

        const result = await pool.query(query, [false]);

        res.status(200).json({
          message: "Sports & Outdoors route is working!",
          products: result.rows,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
    //GET: Toys & Kids API Route
    app.get("/toys-kids", async (req, res) => {
      try {
        const query = `
  SELECT 
    p.id,
    p.product_name,
    p.regular_price,
    p.sale_price,
    p.discount,
    p.rating,
    p.category,
    p.isbestseller,
    p.isnew,
    p.images,
    p.thumbnail,
    p.reviews,
    COALESCE(SUM((pi->>'qty')::INT), 0) AS sold
  FROM products p
  LEFT JOIN orders o
    ON TRUE
  LEFT JOIN LATERAL jsonb_array_elements(o.order_items) AS oi
    ON TRUE
  LEFT JOIN LATERAL jsonb_array_elements(oi->'productinfo') AS pi
    ON pi->>'product_Id' = p.id
  WHERE p.isnew = $1 
    AND p.category = 'Toys & Kids'
  GROUP BY p.id
 ORDER BY RANDOM()
  LIMIT 4;
`;

        const result = await pool.query(query, [false]);

        res.status(200).json({
          message: "Toys & Kids route is working!",
          products: result.rows,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    //GET: Grocery & Food API Route
    app.get("/grocery-food-items", async (req, res) => {
      try {
        const query = `
  SELECT 
    p.id,
    p.product_name,
    p.regular_price,
    p.sale_price,
    p.discount,
    p.rating,
    p.category,
    p.isbestseller,
    p.isnew,
    p.images,
    p.thumbnail,
    p.reviews,
    COALESCE(SUM((pi->>'qty')::INT), 0) AS sold
  FROM products p
  LEFT JOIN orders o
    ON TRUE
  LEFT JOIN LATERAL jsonb_array_elements(o.order_items) AS oi
    ON TRUE
  LEFT JOIN LATERAL jsonb_array_elements(oi->'productinfo') AS pi
    ON pi->>'product_Id' = p.id
  WHERE p.isnew = $1 
    AND p.category = 'Grocery & Food'
  GROUP BY p.id
 ORDER BY RANDOM()
  LIMIT 4;
`;

        const result = await pool.query(query, [false]);

        res.status(200).json({
          message: "Grocery & Food route is working!",
          products: result.rows,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
    //GET: Pet Supplies API Route
    app.get("/pets-pet-care", async (req, res) => {
      try {
        const query = `
  SELECT 
    p.id,
    p.product_name,
    p.regular_price,
    p.sale_price,
    p.discount,
    p.rating,
    p.category,
    p.isbestseller,
    p.isnew,
    p.images,
    p.thumbnail,
    p.reviews,
    COALESCE(SUM((pi->>'qty')::INT), 0) AS sold
  FROM products p
  LEFT JOIN orders o
    ON TRUE
  LEFT JOIN LATERAL jsonb_array_elements(o.order_items) AS oi
    ON TRUE
  LEFT JOIN LATERAL jsonb_array_elements(oi->'productinfo') AS pi
    ON pi->>'product_Id' = p.id
  WHERE p.isnew = $1 
    AND p.category = 'Pet Supplies'
  GROUP BY p.id
 ORDER BY RANDOM()
  LIMIT 4;
`;

        const result = await pool.query(query, [false]);

        res.status(200).json({
          message: "Pet Supplies route is working!",
          products: result.rows,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // Flash Sale Products API Routes

    //GET: Get Active Flash Sale Products

    app.get("/flash-sale/active", async (req, res) => {
      const client = await pool.connect();
      try {
        const nowInSeconds = Math.floor(Date.now() / 1000);
        const buffer = 2;
        await client.query(
          `UPDATE flashSaleProducts SET isactive = false WHERE end_time < $1
`,
          [nowInSeconds],
        );
        const query = `SELECT * FROM flashSaleProducts ORDER BY start_time ASC;`;
        const result = await client.query(query);

        let activeSale = null;

        await client.query("BEGIN"); // transaction শুরু

        for (const sale of result.rows) {
          const start = Number(sale.start_time);
          const end = Number(sale.end_time);

          // const shouldBeActive = nowInSeconds >= start && nowInSeconds < end;
          const shouldBeActive =
            nowInSeconds >= start + buffer && nowInSeconds <= end;

          // ১️⃣ flashSaleProducts.isactive আপডেট
          await client.query(
            `UPDATE flashSaleProducts SET isactive = $1 WHERE id = $2`,
            [shouldBeActive, sale.id],
          );

          const saleProducts = sale.sale_products || [];
          const productIds = saleProducts.map((p) => p.id);

          if (productIds.length > 0) {
            // ২️⃣ মূল products টেবিলের isflashsale আপডেট
            await client.query(
              `UPDATE products SET isflashsale = $1 WHERE id = ANY($2)`,
              [shouldBeActive, productIds],
            );

            // ৩️⃣ flashSaleProducts JSON ফিল্ডের প্রতিটি প্রোডাক্টে isflashsale মান আপডেট
            const updatedSaleProducts = saleProducts.map((p) => ({
              ...p,
              isflashsale: shouldBeActive,
            }));

            await client.query(
              `UPDATE flashSaleProducts SET sale_products = $1 WHERE id = $2`,
              [JSON.stringify(updatedSaleProducts), sale.id],
            );
          }

          if (shouldBeActive && !activeSale) {
            activeSale = { ...sale, sale_products: saleProducts };
          }
        }

        await client.query("COMMIT"); // transaction commit

        if (!activeSale) {
          return res
            .status(200)
            .json({ message: "No active flash sale", active: false });
        }

        res.status(200).json(activeSale);
      } catch (error) {
        await client.query("ROLLBACK");
        console.error("Flash sale error:", error);
        res.status(500).json({ message: "Server error" });
      } finally {
        client.release();
      }
    });

    //POST: Create Flash Sale Products

    // Flash sale creation (same as before, but no setTimeout)
    app.post("/flash-sale", async (req, res) => {
      const client = await pool.connect();

      try {
        const { saleProducts, start_time, end_time } = req.body;

        if (!Array.isArray(saleProducts) || saleProducts.length === 0) {
          return res
            .status(400)
            .json({ message: "saleProducts must be a non-empty array" });
        }

        const now = Math.floor(Date.now() / 1000);
        const startTime = start_time ? Number(start_time) : now;
        const endTime = end_time ? Number(end_time) : now + 12 * 60 * 60;

        if (startTime >= endTime) {
          return res
            .status(400)
            .json({ message: "start_time must be before end_time" });
        }

        await client.query("BEGIN");

        const insertQuery = `
      INSERT INTO flashSaleProducts (isactive, start_time, end_time, sale_products)
      VALUES ($1, $2, $3, $4)
      RETURNING *;
    `;
        const insertValues = [
          false,
          startTime,
          endTime,
          JSON.stringify(saleProducts),
        ];
        const result = await client.query(insertQuery, insertValues);

        await client.query("COMMIT");

        res.status(201).json({
          message: "Flash Sale created successfully",

          createdCount: result.rowCount,
        });
      } catch (error) {
        await client.query("ROLLBACK");
        console.error("[FlashSale] Creation error:", error);
        res.status(500).json({ message: "Server error" });
      } finally {
        client.release();
      }
    });

    //DELETE: Delete Flash Sale by ID

    // DELETE: Entire Flash Sale

    app.delete("/flash-sale/:id", async (req, res) => {
      const client = await pool.connect();

      try {
        const { id } = req.params;
        await client.query("BEGIN");

        // 1️⃣ Fetch flash sale
        const result = await client.query(
          "SELECT sale_products FROM flashSaleProducts WHERE id = $1",
          [id],
        );

        if (result.rowCount === 0) {
          await client.query("ROLLBACK");
          return res.status(404).json({ message: "Flash sale not found" });
        }

        const saleProducts = result.rows[0].sale_products;

        // 2️⃣ Restore stock
        for (const flashProd of saleProducts) {
          const productId = flashProd.id; // ✅ FIX

          // 🔹 Variant-based product
          if (flashProd.variants && flashProd.variants.length > 0) {
            for (const fv of flashProd.variants) {
              await client.query(
                `UPDATE product_variants
             SET stock = stock + $1
             WHERE id = $2`,
                [Number(fv.stock) || 0, fv.id],
              );
            }

            // Update main product stock from variants
            const totalStockRes = await client.query(
              `SELECT COALESCE(SUM(stock),0) AS total
           FROM product_variants
           WHERE product_id = $1`,
              [productId],
            );

            await client.query(
              `UPDATE products
           SET stock = $1,
               isflashsale = false
           WHERE id = $2`,
              [totalStockRes.rows[0].total, productId],
            );
          }

          // 🔹 Single product
          else {
            await client.query(
              `UPDATE products
           SET stock = stock + $1,
               isflashsale = false
           WHERE id = $2`,
              [Number(flashProd.stock) || 0, productId],
            );
          }

          // 3️⃣ Update carts
          await client.query(
            `
        UPDATE carts
        SET productinfo = (
          SELECT jsonb_agg(
            CASE
              WHEN prod->>'product_Id' = $1
              THEN prod || jsonb_build_object(
                'isflashsale', false,
                'sale_price', $2::numeric,
                'regular_price', $3::numeric
              )
              ELSE prod
            END
          )
          FROM jsonb_array_elements(productinfo) prod
        )
        WHERE EXISTS (
          SELECT 1
          FROM jsonb_array_elements(productinfo) prod
          WHERE prod->>'product_Id' = $1
        )
        `,
            [
              productId,
              flashProd.sale_price || 0,
              flashProd.regular_price || 0,
            ],
          );
        }

        // 4️⃣ Delete flash sale
        await client.query("DELETE FROM flashSaleProducts WHERE id = $1", [id]);

        await client.query("COMMIT");

        res.status(200).json({
          message: "Flash sale deleted & stocks restored successfully",
        });
      } catch (error) {
        await client.query("ROLLBACK");
        console.error(error);
        res.status(500).json({ message: error.message });
      } finally {
        client.release();
      }
    });

    // DELETE: Delete single Flash Sale Product
    app.delete("/flash-sale/products/:id", async (req, res) => {
      const { id } = req.params;
      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        // 1️⃣ flash sale product বের করা
        const flashRes = await client.query(
          `
      SELECT f.id AS flashsale_id, item
      FROM flashSaleProducts f,
           jsonb_array_elements(f.sale_products) AS item
      WHERE item->>'id' = $1
      `,
          [id],
        );

        if (flashRes.rowCount === 0) {
          throw new Error("Flash sale product not found");
        }

        const flashProduct = flashRes.rows[0].item;
        const flashSaleId = flashRes.rows[0].flashsale_id;

        // 2️⃣ main product
        const productRes = await client.query(
          `SELECT * FROM products WHERE id = $1`,
          [flashProduct.id],
        );

        if (productRes.rowCount > 0) {
          const mainProduct = productRes.rows[0];

          // 3️⃣ variant update (product_variants table)
          const variantRes = await client.query(
            `SELECT * FROM product_variants WHERE product_id = $1`,
            [mainProduct.id],
          );

          const variants = variantRes.rows;

          if (variants.length && flashProduct.variants?.length) {
            // Flash sale stock restore
            for (const fv of flashProduct.variants) {
              const v = variants.find((v) => v.id === fv.id);
              if (v) {
                await client.query(
                  `UPDATE product_variants SET stock = $1 WHERE id = $2`,
                  [(v.stock || 0) + (fv.stock || 0), v.id],
                );
              }
            }

            // Update main product stock = sum of variant stock
            const totalStockRes = await client.query(
              `SELECT COALESCE(SUM(stock),0) AS total_stock FROM product_variants WHERE product_id = $1`,
              [mainProduct.id],
            );
            mainProduct.stock = totalStockRes.rows[0].total_stock;
          } else {
            // Single product restore
            mainProduct.stock =
              (mainProduct.stock || 0) + (flashProduct.stock || 0);
          }

          // 4️⃣ main product update
          await client.query(
            `UPDATE products SET stock=$1, isflashsale=false WHERE id=$2`,
            [mainProduct.stock, mainProduct.id],
          );

          // 5️⃣ carts update
          await client.query(
            `
        UPDATE carts
        SET productinfo = (
          SELECT jsonb_agg(
            CASE
              WHEN prod->>'product_Id' = $1
              THEN prod || jsonb_build_object(
                'isflashsale', false,
                'sale_price', $2::numeric,
                'regular_price', $3::numeric
              )
              ELSE prod
            END
          )
          FROM jsonb_array_elements(productinfo) prod
        )
        WHERE EXISTS (
          SELECT 1
          FROM jsonb_array_elements(productinfo) prod
          WHERE prod->>'product_Id' = $1
        )
        `,
            [
              mainProduct.id,
              mainProduct.sale_price || 0,
              mainProduct.regular_price || 0,
            ],
          );
        }

        // 6️⃣ remove product from flash sale
        await client.query(
          `
      UPDATE flashSaleProducts
      SET sale_products = (
        SELECT COALESCE(jsonb_agg(item), '[]'::jsonb)
        FROM jsonb_array_elements(sale_products) item
        WHERE item->>'id' <> $1
      )
      WHERE id = $2
      `,
          [id, flashSaleId],
        );

        // 7️⃣ delete empty flash sales
        await client.query(
          `DELETE FROM flashSaleProducts WHERE sale_products = '[]'::jsonb`,
        );

        await client.query("COMMIT");

        res.status(200).json({
          message: "Flash sale product deleted, stock restored & cart updated",
        });
      } catch (error) {
        await client.query("ROLLBACK");
        console.error(error);
        res.status(500).json({ message: error.message });
      } finally {
        client.release();
      }
    });

    //POST: Create a new flash sale setting
    app.post("/flash-sale/toggle-auto", async (req, res) => {
      const { enable } = req.body;
      try {
        const existing = await pool.query(
          "SELECT * FROM flash_sale_settings LIMIT 1;",
        );
        if (existing.rows.length) {
          return res
            .status(400)
            .json({ success: false, message: "Already exists" });
        }

        const result = await pool.query(
          `INSERT INTO flash_sale_settings (is_auto_enabled, last_updated) 
       VALUES ($1, NOW())
       RETURNING *;`,
          [enable],
        );
        res.status(201).json({ success: true, setting: result.rowCount });
      } catch (err) {
        res.status(500).json({ success: false, message: err.message });
      }
    });

    //PUT: Turn auto flash sale on/off
    app.put("/flash-sale/toggle-auto", async (req, res) => {
      const { enable } = req.body;
      try {
        const result = await pool.query(
          "UPDATE flash_sale_settings SET is_auto_enabled=$1 WHERE id=1",
          [enable],
        );
        res.json({ success: true, enable });
      } catch (err) {
        res.status(500).json({ success: false, message: err.message });
      }
    });
    // GET: GET Flashsale Toggle
    app.get(
      "/flash-sale/toggle-auto",
      passport.authenticate("jwt", { session: false }),
      verifyAdmin,
      async (req, res) => {
        try {
          const query = `
     SELECT is_auto_enabled FROM flash_sale_settings WHERE id=1;
    `;
          const result = await pool.query(query);

          res.status(200).json(result.rows[0]);
        } catch (error) {
          console.error(error);
          res.status(500).json({ message: "Server error" });
        }
      },
    );

    // ------------ Products API Routes End ----------------//

    // ------------ Inventory API Routes ------------//
    // GET: Get Inventory
    app.get(
      "/inventory/:sellerId",
      passport.authenticate("jwt", { session: false }),

      async (req, res) => {
        try {
          const { sellerId } = req.params;

          if (req.user.role === "seller" && sellerId !== req.user.id) {
            return res.status(401).send("unauthorized access");
          }
          if (req.user.role === "seller" || req.user.role === "super admin") {
            const query = `
  SELECT
    p.id,
    p.product_name,
    p.category,
    p.subcategory,
    p.subcategory_item,
    p.stock,
   
    COALESCE(
      jsonb_agg(
        DISTINCT jsonb_strip_nulls(
          jsonb_build_object(
            'id', v.id,
            'regular_price', v.regular_price,
            'sale_price', v.sale_price,
            'stock', v.stock
          ) || v.attributes
        )
      ) FILTER (WHERE v.id IS NOT NULL),
      '[]'
    ) AS variants
  FROM products p
  LEFT JOIN product_variants v
    ON v.product_id = p.id
  WHERE p.seller_id = $1
  GROUP BY p.id
  ORDER BY p.stock ASC;
`;

            const result = await pool.query(query, [sellerId]);
            return res.status(200).json({
              message: "Return Inventory Successfully Done",
              inventory: result.rows,
            });
          } else {
            const query = `SELECT
    p.id,
    p.product_name,
    p.category,
    p.subcategory,
    p.subcategory_item,
    p.stock,
   
    COALESCE(
      jsonb_agg(
        DISTINCT jsonb_strip_nulls(
          jsonb_build_object(
            'id', v.id,
            'regular_price', v.regular_price,
            'sale_price', v.sale_price,
            'stock', v.stock
          ) || v.attributes
        )
      ) FILTER (WHERE v.id IS NOT NULL),
      '[]'
    ) AS variants
  FROM products p
  LEFT JOIN product_variants v
    ON v.product_id = p.id
  WHERE seller_role='super admin'
  GROUP BY p.id
  ORDER BY p.stock ASC;`;
            const result = await pool.query(query);

            return res.status(200).json({
              message: "Return Inventory Successfully Done",
              inventory: result.rows,
            });
          }
        } catch (error) {
          res.status(500).json({
            message: error.message,
          });
        }
      },
    );

    // PATCH: Update Inventory Products Stocks

    app.patch(
      "/inventory/:sellerId",
      passport.authenticate("jwt", { session: false }),
      async (req, res) => {
        try {
          const { productId, variantId, change } = req.body;
          const { sellerId } = req.params;

          if (!productId || typeof change !== "number") {
            return res.status(400).json({
              message: "productId & change are required",
            });
          }

          const isModerator =
            req.user.role === "moderator" || req.user.role === "admin";

          // Fetch product
          const productQuery = isModerator
            ? `SELECT id, seller_id, product_name, stock FROM products WHERE id = $1`
            : `SELECT id, seller_id, product_name, stock FROM products WHERE id = $1 AND seller_id = $2`;

          const productResult = await pool.query(
            productQuery,
            isModerator ? [productId] : [productId, sellerId],
          );

          if (productResult.rows.length === 0)
            return res.status(404).json({ message: "Product not found" });

          const { seller_id, product_name, stock } = productResult.rows[0];

          /** ------------------------------------------------
           * 🔹 CASE 1: No variant → update main product stock
           * ------------------------------------------------*/
          if (!variantId) {
            const newStock = Math.max(stock + change, 0);

            // Notifications
            if (newStock === 0) {
              await createNotification({
                userId: seller_id,
                userRole: "seller",
                title: "Product Out of Stock",
                message: `${product_name} has run out of stock.`,
                type: "out_of_stock",
                refId: productId,
                refData: { newStock },
                expiresAt: "2d",
              });
            } else if (newStock <= 5) {
              await createNotification({
                userId: seller_id,
                userRole: "seller",
                title: "Low Stock Warning",
                message: `${product_name} stock is low. Only ${newStock} items left.`,
                type: "low_stock",
                refId: productId,
                refData: { newStock },
                expiresAt: "2d",
              });
            }

            const updateResult = await pool.query(
              `UPDATE products SET stock = $1 WHERE id = $2`,
              [newStock, productId],
            );

            return res.json({
              message: "Product stock updated (no variants)",
              totalStock: newStock,
              updatedCount: updateResult.rowCount,
            });
          }

          /** ------------------------------------------------
           * 🔹 CASE 2: Variant exists → update variant stock
           * ------------------------------------------------*/
          const variantResult = await pool.query(
            `SELECT id, product_id, attributes, regular_price, sale_price, stock
         FROM product_variants
         WHERE id = $1 AND product_id = $2`,
            [variantId, productId],
          );

          if (variantResult.rows.length === 0)
            return res.status(404).json({ message: "Variant not found" });

          const variant = variantResult.rows[0];
          const newVariantStock = Math.max(variant.stock + change, 0);

          // Update variant stock
          await pool.query(
            `UPDATE product_variants SET stock = $1 WHERE id = $2`,
            [newVariantStock, variantId],
          );

          // Calculate total stock across all variants
          const totalStockResult = await pool.query(
            `SELECT COALESCE(SUM(stock),0) as total_stock FROM product_variants WHERE product_id = $1`,
            [productId],
          );

          const totalStock = totalStockResult.rows[0].total_stock;

          // Update products.stock for reference
          await pool.query(`UPDATE products SET stock = $1 WHERE id = $2`, [
            totalStock,
            productId,
          ]);

          // Notifications
          if (newVariantStock === 0) {
            await createNotification({
              userId: seller_id,
              userRole: "seller",
              title: "Product Out of Stock",
              message: `${product_name} variant is out of stock.`,
              type: "out_of_stock",
              refId: productId,
              refData: { variantId, newStock: newVariantStock },
              expiresAt: "2d",
            });
          } else if (newVariantStock <= 5) {
            await createNotification({
              userId: seller_id,
              userRole: "seller",
              title: "Low Stock Warning",
              message: `${product_name} variant stock is low. Only ${newVariantStock} items left.`,
              type: "low_stock",
              refId: productId,
              refData: { variantId, newStock: newVariantStock },
              expiresAt: "2d",
            });
          }

          res.json({
            message: "Variant & total stock updated",
            variantId,
            newVariantStock,
            totalStock,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // PATCH: Update Inventory All Products Stocks
    app.patch(
      "/inventory/all-variants/:sellerId",
      passport.authenticate("jwt", { session: false }),
      async (req, res) => {
        try {
          const { change, productId } = req.body;
          const { sellerId } = req.params;

          if (typeof change !== "number") {
            return res.status(400).json({ message: "Invalid change value" });
          }

          // Admin / Moderator check
          const isModerator =
            req.user.role === "moderator" || req.user.role === "admin";

          const productQuery = isModerator
            ? `SELECT id, seller_id, product_name, stock 
           FROM products 
           WHERE seller_role='super admin' AND id=$1`
            : `SELECT id, seller_id, product_name, stock 
           FROM products 
           WHERE seller_id=$1 AND id=$2`;

          const productResult = await pool.query(
            productQuery,
            isModerator ? [productId] : [sellerId, productId],
          );

          if (!productResult.rows.length) {
            return res.status(404).json({ message: "Product not found" });
          }

          const product = productResult.rows[0];

          // Fetch variants
          const { rows: variants } = await pool.query(
            "SELECT id, stock FROM product_variants WHERE product_id=$1",
            [productId],
          );

          /* =====================================================
         CASE 1: ❌ No Variants → Update Main Product Stock
      ====================================================== */
          if (variants.length === 0) {
            const newStock = Math.max((product.stock || 0) + change, 0);

            // Notifications
            if (newStock === 0) {
              await createNotification({
                userId: product.seller_id,
                userRole: "seller",
                title: "Product Out of Stock",
                message: `${product.product_name} is OUT OF STOCK.`,
                type: "out_of_stock",
                refId: productId,
                refData: { newStock },
                expiresAt: "2d",
              });
            } else if (newStock <= 5) {
              await createNotification({
                userId: product.seller_id,
                userRole: "seller",
                title: "Low Stock Warning",
                message: `${product.product_name} LOW STOCK: Only ${newStock} left.`,
                type: "low_stock",
                refId: productId,
                refData: { newStock },
                expiresAt: "2d",
              });
            }

            await pool.query("UPDATE products SET stock=$1 WHERE id=$2", [
              newStock,
              productId,
            ]);

            return res.json({
              updated: true,
              totalStock: newStock,
              updatedVariants: [],
              message: "Main product stock updated (no variants)",
            });
          }

          /* =====================================================
         CASE 2: ✅ Variants Exist → Update All Variants
      ====================================================== */
          const updatedVariants = await Promise.all(
            variants.map(async (v) => {
              const newStock = Math.max((v.stock || 0) + change, 0);

              // Variant notifications
              if (newStock === 0) {
                await createNotification({
                  userId: product.seller_id,
                  userRole: "seller",
                  title: "Variant Out of Stock",
                  message: `Variant ${v.id} of ${product.product_name} is OUT OF STOCK.`,
                  type: "out_of_stock",
                  refId: productId,
                  refData: { variantId: v.id, newStock },
                  expiresAt: "2d",
                });
              } else if (newStock <= 5) {
                await createNotification({
                  userId: product.seller_id,
                  userRole: "seller",
                  title: "Low Stock Warning",
                  message: `Variant ${v.id} of ${product.product_name} LOW STOCK: Only ${newStock} left.`,
                  type: "low_stock",
                  refId: productId,
                  refData: { variantId: v.id, newStock },
                  expiresAt: "2d",
                });
              }

              await pool.query(
                "UPDATE product_variants SET stock=$1 WHERE id=$2",
                [newStock, v.id],
              );

              return { ...v, stock: newStock };
            }),
          );

          // Recalculate main product stock
          const totalStock = updatedVariants.reduce(
            (sum, v) => sum + v.stock,
            0,
          );

          await pool.query("UPDATE products SET stock=$1 WHERE id=$2", [
            totalStock,
            productId,
          ]);

          res.json({
            updated: true,
            totalStock,
            updatedVariants,
            message: "All variant stocks updated successfully",
          });
        } catch (err) {
          console.error(err);
          res.status(500).json({ message: err.message });
        }
      },
    );

    // ------------ Inventory API Routes End ------------//

    // ------------ Seller API Routes ------------//
    // POST: Create Seller API Route
    app.post(
      "/create-sellers",
      upload.fields([
        { name: "profileImg", maxCount: 1 },
        { name: "nidFrontImg", maxCount: 1 },
        { name: "nidBackImg", maxCount: 1 },
      ]),
      async (req, res) => {
        try {
          const sellerInfo = req.body;
          const files = req.files;

          const email = sellerInfo.email;
          if (!email)
            return res.status(400).json({ message: "Email is required" });

          // Check duplicate email
          const checkQuery = `
        SELECT 'admins' AS type FROM admins WHERE email = $1
        UNION
        SELECT 'users' AS type FROM users WHERE email = $1
        UNION
        SELECT 'sellers' AS type FROM sellers WHERE email = $1
      `;
          const checkResult = await pool.query(checkQuery, [email]);
          if (checkResult.rowCount > 0)
            return res.status(400).json({ message: "Email already exists" });

          // Email & Password validation
          if (!emailRegex.test(email))
            return res.status(400).json({ message: "Invalid email format" });

          if (!passwordRegex.test(sellerInfo.password))
            return res.status(400).json({
              message: "Password must be min 8 chars with letters & numbers",
            });

          // Hash password
          const hashedPassword = await bcrypt.hash(sellerInfo.password, 12);

          // Process uploaded files
          const uploadDir = path.join(
            __dirname,
            "uploads",
            "sellers",
            `${sellerInfo.full_Name}`,
          );
          if (!fs.existsSync(uploadDir))
            fs.mkdirSync(uploadDir, { recursive: true });

          const saveMulterImage = async (file, prefix) => {
            if (!file) return null;
            const safeName =
              sellerInfo.full_Name?.replace(/\s+/g, "_") || "seller";
            const filename = `${safeName}_${prefix}_${uuidv4()}.webp`;
            const filepath = path.join(uploadDir, filename);
            await sharp(file.buffer).webp({ lossless: true }).toFile(filepath);
            return `/uploads/sellers/${sellerInfo.full_Name}/${filename}`;
          };

          const profileImgPath = await saveMulterImage(
            files?.profileImg?.[0],
            "profile",
          );
          const nidFrontPath = await saveMulterImage(
            files?.nidFrontImg?.[0],
            "nid_front",
          );
          const nidBackPath = await saveMulterImage(
            files?.nidBackImg?.[0],
            "nid_back",
          );

          // Prepare temp_data for OTP verification
          const sellerId = generateId("SEL");
          const userName = await generateUsername(sellerInfo.email, pool);

          const query = `INSERT INTO sellers (
      id, email, user_name, password, full_name, phone_number, img,
      nid_number, store_name, product_category, business_address, district, thana,
      postal_code, trade_license_number, nid_front_file, nid_back_file, bank_name,
      branch_name, account_number, account_holder_name, routing_number, mobile_bank_name,
      mobile_bank_account_number, created_at, status,role, date_of_birth, gender
    ) VALUES (
      $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
      $14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,NOW(),$25,$26,$27,$28
    ) RETURNING *;`;

          const values = [
            sellerId,
            email,
            userName,
            hashedPassword,
            sellerInfo.full_Name,
            sellerInfo.phone_number || null,
            profileImgPath || null,
            sellerInfo.nidNumber || null,
            sellerInfo.storeName || null,
            sellerInfo.product_category || null,
            sellerInfo.businessAddress || null,
            sellerInfo.district || null,
            sellerInfo.thana || null,
            sellerInfo.postal_code || null,
            sellerInfo.tradeLicenseNumber || null,
            nidFrontPath || null,
            nidBackPath || null,
            sellerInfo.bankName || null,
            sellerInfo.branchName || null,
            sellerInfo.accountNumber || null,
            sellerInfo.accountHolderName || null,
            sellerInfo.routingNumber || null,
            sellerInfo.mobile_bank_name || null,
            sellerInfo.mobileBankAccountNumber || null,
            "approved",
            "seller",
            sellerInfo.date_of_birth || null,
            sellerInfo.gender || null,
          ];

          const insertedSeller = await pool.query(query, values);
          res.status(201).json({
            message: "Seller created successfully",

            createdCount: insertedSeller.rowCount,
          });
        } catch (error) {
          res.status(500).json({ message: "Internal server error" });
        }
      },
    );
    app.post(
      "/sellers",
      upload.fields([
        { name: "profileImg", maxCount: 1 },
        { name: "nidFrontImg", maxCount: 1 },
        { name: "nidBackImg", maxCount: 1 },
      ]),
      async (req, res) => {
        try {
          const sellerInfo = req.body;
          const files = req.files;

          const email = sellerInfo.email;
          if (!email)
            return res.status(400).json({ message: "Email is required" });

          // Check duplicate email
          const checkQuery = `
        SELECT 'admins' AS type FROM admins WHERE email = $1
        UNION
        SELECT 'users' AS type FROM users WHERE email = $1
        UNION
        SELECT 'sellers' AS type FROM sellers WHERE email = $1
      `;
          const checkResult = await pool.query(checkQuery, [email]);
          if (checkResult.rowCount > 0)
            return res.status(400).json({ message: "Email already exists" });

          // Email & Password validation
          if (!emailRegex.test(email))
            return res.status(400).json({ message: "Invalid email format" });

          if (!passwordRegex.test(sellerInfo.password))
            return res.status(400).json({
              message: "Password must be min 8 chars with letters & numbers",
            });

          // Hash password
          const hashedPassword = await bcrypt.hash(sellerInfo.password, 12);

          // Process uploaded files
          const uploadDir = path.join(
            __dirname,
            "uploads",
            "sellers",
            `${sellerInfo.full_Name}`,
          );
          if (!fs.existsSync(uploadDir))
            fs.mkdirSync(uploadDir, { recursive: true });

          const saveMulterImage = async (file, prefix) => {
            if (!file) return null;
            const safeName =
              sellerInfo.full_Name?.replace(/\s+/g, "_") || "seller";
            const filename = `${safeName}_${prefix}_${uuidv4()}.webp`;
            const filepath = path.join(uploadDir, filename);
            await sharp(file.buffer).webp({ lossless: true }).toFile(filepath);
            return `/uploads/sellers/${sellerInfo.full_Name}/${filename}`;
          };

          const profileImgPath = await saveMulterImage(
            files?.profileImg?.[0],
            "profile",
          );
          const nidFrontPath = await saveMulterImage(
            files?.nidFrontImg?.[0],
            "nid_front",
          );
          const nidBackPath = await saveMulterImage(
            files?.nidBackImg?.[0],
            "nid_back",
          );

          // Prepare temp_data for OTP verification
          const sellerId = generateId("SEL");
          const tempData = {
            id: sellerId,
            email,
            user_name: await generateUsername(sellerInfo.email, pool),
            password: hashedPassword,
            full_Name: sellerInfo.full_Name,
            phone_number: sellerInfo.phone_number || null,
            profileImg: profileImgPath,
            nidFront: nidFrontPath,
            nidBack: nidBackPath,
            storeName: sellerInfo.storeName || null,
            product_category: sellerInfo.product_category || null,
            nidNumber: sellerInfo.nidNumber || null,
            businessAddress: sellerInfo.businessAddress || null,
            district: sellerInfo.district || null,
            thana: sellerInfo.thana || null,
            postal_code: sellerInfo.postal_code || null,
            tradeLicenseNumber: sellerInfo.tradeLicenseNumber || null,
            bankName: sellerInfo.bankName || null,
            branchName: sellerInfo.branchName || null,
            accountNumber: sellerInfo.accountNumber || null,
            accountHolderName: sellerInfo.accountHolderName || null,
            routingNumber: sellerInfo.routingNumber || null,
            mobile_bank_name: sellerInfo.mobile_bank_name || null,
            mobileBankAccountNumber: sellerInfo.mobileBankAccountNumber || null,
            date_of_birth: sellerInfo.date_of_birth || null,
            gender: sellerInfo.gender || null,
          };

          // Generate OTP
          const otp = crypto.randomInt(100000, 999999).toString();
          const expiresAt = new Date(Date.now() + 1 * 60 * 1000); // 5 minutes

          // Remove old OTP if exists
          await pool.query("DELETE FROM email_otps WHERE email=$1", [email]);

          // Save OTP + temp_data
          await pool.query(
            "INSERT INTO email_otps (email, otp, expires_at, temp_data) VALUES ($1,$2,$3,$4)",
            [email, otp, expiresAt, JSON.stringify(tempData)],
          );

          // Send OTP email
          await sendEmail(
            email,
            "OTP for Seller Registration",
            `<div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 10px; background-color: #f9f9f9;">
  <h2 style="color: #FF0055; text-align: center;">Bazarigo</h2>
  <p>Hi there,</p>
  <p>Use the following One-Time Password (OTP) to complete your <strong>Seller Registration</strong> on Bazaarigo. This OTP is valid for <strong>1 minute</strong>.</p>
  <p style="text-align: center; margin: 30px 0;">
    <span style="font-size: 28px; font-weight: bold; letter-spacing: 4px; color: #FF0055;">${otp}</span>
  </p>
  <p>If you did not request this, please ignore this email.</p>
  <hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">
  <p style="font-size: 12px; color: #777; text-align: center;">
    &copy; ${new Date().getFullYear()} Bazaarigo. All rights reserved.
  </p>
</div>
`,
          );

          return res.status(200).json({
            message: "OTP sent to your email",
            otp_required: true,
          });
        } catch (error) {
          res.status(500).json({ message: "Internal server error" });
        }
      },
    );

    // PUT: Seller Settings API Route

    app.put(
      "/sellers/update/:id",
      upload.fields([
        { name: "profileImg", maxCount: 1 },
        { name: "storeImg", maxCount: 1 },
        { name: "nidFrontImg", maxCount: 1 },
        { name: "nidBackImg", maxCount: 1 },
      ]),
      async (req, res) => {
        try {
          const sellerId = req.params.id;
          const payload = req.body;
          const files = req.files;

          // Fetch old seller
          const { rows } = await pool.query(
            "SELECT * FROM sellers WHERE id=$1",
            [sellerId],
          );
          if (rows.length === 0)
            return res.status(404).json({ message: "Seller not found" });

          const oldSeller = rows[0];

          // Upload dir
          const uploadDir = path.join(__dirname, "uploads", "sellers");
          if (!fs.existsSync(uploadDir))
            fs.mkdirSync(uploadDir, { recursive: true });

          // Save Multer buffer → webp helper
          const saveMulterImage = async (file, prefix, name) => {
            if (!file) return null;
            const safeName = name?.replace(/\s+/g, "_") || "seller";
            const filename = `${safeName}_${prefix}_${uuidv4()}.webp`;
            const filepath = path.join(uploadDir, filename);

            await sharp(file.buffer).webp({ quality: 80 }).toFile(filepath);

            return `/uploads/sellers/${filename}`;
          };

          const profile_imgPath = await saveMulterImage(
            files?.profileImg?.[0],
            "profile",
            payload.full_name || oldSeller.full_name,
          );

          const store_imgPath = await saveMulterImage(
            files?.storeImg?.[0],
            "store",
            payload.store_name || oldSeller.store_name,
          );

          const nid_front_filePath = await saveMulterImage(
            files?.nidFrontImg?.[0],
            "nid_front",
            payload.full_name || oldSeller.full_name,
          );

          const nid_back_filePath = await saveMulterImage(
            files?.nidBackImg?.[0],
            "nid_back",
            payload.full_name || oldSeller.full_name,
          );

          // Password hash
          let hashedPassword = oldSeller.password;
          if (payload.old_password && payload.new_password) {
            const match = await bcrypt.compare(
              payload.old_password,
              oldSeller.password,
            );
            if (!match)
              return res
                .status(400)
                .json({ message: "Old password incorrect" });
            hashedPassword = await bcrypt.hash(payload.new_password, 10);
          }

          // Update query
          const query = `
        UPDATE sellers
        SET 
          full_name=$1,
          email=$2,
          password=$3,
          phone_number=$4,
          date_of_birth=$5,
          gender=$6,
          img=$7,
          nid_number=$8,
          store_name=$9,
          product_category=$10,
          business_address=$11,
          district=$12,
          thana=$13,
          postal_code=$14,
          trade_license_number=$15,
          nid_front_file=$16,
          nid_back_file=$17,
          bank_name=$18,
          branch_name=$19,
          account_number=$20,
          account_holder_name=$21,
          routing_number=$22,
          mobile_bank_name=$23,
          mobile_bank_account_number=$24,
          store_img=$25,
          updated_at=NOW()
        WHERE id=$26
        RETURNING *;
      `;

          const values = [
            payload.full_name || oldSeller.full_name,
            payload.email || oldSeller.email,
            hashedPassword,
            payload.phone_number || oldSeller.phone_number,
            payload.date_of_birth || oldSeller.date_of_birth,
            payload.gender || oldSeller.gender,
            profile_imgPath || oldSeller.img,
            payload.nid_number || oldSeller.nid_number,
            payload.store_name || oldSeller.store_name,
            payload.product_category || oldSeller.product_category,
            payload.business_address || oldSeller.business_address,
            payload.district || oldSeller.district,
            payload.thana || oldSeller.thana,
            payload.postal_code || oldSeller.postal_code,
            payload.trade_license_number || oldSeller.trade_license_number,
            nid_front_filePath || oldSeller.nid_front_file,
            nid_back_filePath || oldSeller.nid_back_file,
            payload.bank_name || oldSeller.bank_name,
            payload.branch_name || oldSeller.branch_name,
            payload.account_number || oldSeller.account_number,
            payload.account_holder_name || oldSeller.account_holder_name,
            payload.routing_number || oldSeller.routing_number,
            payload.mobile_bank_name || oldSeller.mobile_bank_name,
            payload.mobile_bank_account_number ||
              oldSeller.mobile_bank_account_number,
            store_imgPath || oldSeller.store_img,
            sellerId,
          ];

          const result = await pool.query(query, values);
          if (result.rowCount > 0) {
            // Update seller store name in products table
            const updateProductsQuery = `
              UPDATE products
              SET seller_store_name = $1,
              seller_name = $2
              WHERE seller_id = $3;
            `;
            await pool.query(updateProductsQuery, [
              payload.store_name || oldSeller.store_name,
              payload.full_name || oldSeller.full_name,
              sellerId,
            ]);
          }

          return res.status(200).json({
            message: "Seller updated successfully",
            seller: result.rows[0],
            updatedCount: result.rowCount,
          });
        } catch (error) {
          res.status(500).json({ message: "Internal server error" });
        }
      },
    );
    // PATCH: Update Seller Review API Route
    app.patch("/sellers/review/:id", async (req, res) => {
      try {
        const { id } = req.params;
        const review = req.body; // expect { customerName, rating, comment ... }

        // Existing reviews fetch
        const selectSellerQuery = `SELECT reviews FROM sellers WHERE id = $1`;
        const selectSellerResult = await pool.query(selectSellerQuery, [id]);
        const selectAdminQuery = `SELECT reviews FROM admins WHERE id = $1`;
        const selectAdminResult = await pool.query(selectAdminQuery, [id]);

        if (
          selectSellerResult.rowCount === 0 &&
          selectAdminResult.rowCount === 0
        ) {
          return res.status(404).json({ message: "Seller not found" });
        }

        const existingReviews =
          selectSellerResult.rows[0]?.reviews ||
          selectAdminResult.rows[0]?.reviews ||
          [];
        const updatedReviews = [...existingReviews, review];

        // Seller টেবিলে আপডেট
        const sellerResult = await pool.query(
          "UPDATE sellers SET reviews = $1 WHERE id = $2",
          [updatedReviews, id],
        );

        // Admin টেবিলে আপডেট
        const adminResult = await pool.query(
          "UPDATE admins SET reviews = $1 WHERE id = $2",
          [updatedReviews, id],
        );

        res.status(200).json({
          message: "Review updated successfully",
          updatedCount: sellerResult.rowCount + adminResult.rowCount,
        });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: error.message });
      }
    });

    // PATCH: Update Seller Status API Route
    app.patch("/sellers/:id/status", async (req, res) => {
      try {
        const sellerId = req.params.id;
        const { status } = req.body;
        const sellerData = await pool.query(
          "SELECT full_name, email FROM sellers WHERE id = $1",
          [sellerId],
        );

        const seller = sellerData.rows[0];
        if (!seller) {
          return res.status(404).json({ message: "Seller not found" });
        }

        // If rejected → delete seller
        if (status === "rejected") {
          const deleteQuery = "DELETE FROM sellers WHERE id = $1;";
          const deleteRes = await pool.query(deleteQuery, [sellerId]);
          if (deleteRes.rowCount > 0) {
            // Notification for rejection
            await createNotification({
              userId: sellerId,
              userRole: "seller",
              title: "Account Rejected",
              message:
                "Your seller account has been rejected. Please contact support.",
              type: "status",
              refId: sellerId,
              expiresAt: "7d",
            });
            // Send rejection email
            await sendEmail(
              seller.email,
              "Seller Application Rejected",
              `
<div style="font-family: Arial, sans-serif; max-width:600px; margin:auto; padding:25px; border:1px solid #eee; border-radius:10px;">
<h2 style="text-align:center;color:#FF0055;">Bazarigo</h2>

<p>Hello <strong>${seller.full_name}</strong>,</p>

<p>Thank you for applying to become a seller on <strong>Bazarigo</strong>.</p>

<p>Unfortunately, your seller application has been <strong>rejected</strong> after review.</p>

<p>If you believe this was a mistake or need more information, please contact our support team.</p>

<hr/>

<p style="font-size:12px;color:#777;text-align:center;">
© ${new Date().getFullYear()} Bazarigo. All rights reserved.
</p>
</div>
`,
            );

            return res.status(200).json({
              message: `Seller rejected and deleted successfully.`,
              deletedCount: deleteRes.rowCount,
            });
          }
        }

        // If approved → update status + role
        if (status === "approved") {
          const approveQuery =
            "UPDATE sellers SET status = $1, role = 'seller' WHERE id = $2;";
          const approveRes = await pool.query(approveQuery, [status, sellerId]);

          if (approveRes.rowCount > 0) {
            // Notification for approval
            await createNotification({
              userId: sellerId,
              userRole: "seller",
              title: "Account Approved",
              message:
                "Your seller account has been approved. You can now start selling.",
              type: "status",
              refId: sellerId,
              expiresAt: "7d",
            });
            // Send approval email
            await sendEmail(
              seller.email,
              "Seller Account Approved",
              `
<div style="font-family: Arial, sans-serif; max-width:600px; margin:auto; padding:25px; border:1px solid #eee; border-radius:10px;">
<h2 style="text-align:center;color:#FF0055;">Bazarigo</h2>

<p>Hello <strong>${seller.full_name}</strong>,</p>

<p>Congratulations! Your seller account on <strong>Bazarigo</strong> has been <strong>approved</strong>.</p>

<p>You can now log in and start adding products to begin selling.</p>

<p>We wish you great success on our platform.</p>

<hr/>

<p style="font-size:12px;color:#777;text-align:center;">
© ${new Date().getFullYear()} Bazarigo. All rights reserved.
</p>
</div>
`,
            );

            return res.status(200).json({
              message: `Seller approved successfully.`,
              updatedCount: approveRes.rowCount,
            });
          }
        }

        res.status(400).json({ message: "Invalid status value" });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // GET: Get Sellers API Route
    app.get(
      "/sellers",
      passport.authenticate("jwt", { session: false }),
      verifyAdmin,
      async (req, res) => {
        try {
          const query = "SELECT * FROM sellers;";
          const result = await pool.query(query);
          res.status(200).json({
            message: "Sellers route is working!",
            sellers: result.rows,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );
    // GET: Get Seller By Id API Route
    app.get(
      "/sellers/:id",
      passport.authenticate("jwt", { session: false }),

      async (req, res) => {
        try {
          const { id } = req.params;

          const query = ` 
        SELECT id,email,user_name,full_name,phone_number,store_img,store_name,product_category,reviews,role  FROM admins WHERE id = $1
        UNION
        SELECT id,email,user_name,full_name,phone_number,store_img,store_name,product_category,reviews,role  FROM sellers WHERE id = $1
      
        ;`;
          const result = await pool.query(query, [id]);
          res.status(200).json({
            message: "Sellers route is working!",
            seller: result.rows[0],
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );
    // Delete: Delete Seller By Id API Route
    app.delete("/sellers/bulk", async (req, res) => {
      try {
        const { ids } = req.body; // expects array of IDs

        if (!ids || !ids.length)
          return res.status(400).json({ message: "No IDs provided" });

        const query = "DELETE FROM sellers WHERE id = ANY($1)";
        const result = await pool.query(query, [ids]);
        if (result.rowCount > 0) {
          const deleteProductsQuery = `
  DELETE FROM products WHERE seller_id = ANY($1);
    
  `;
          const deletedProducts = await pool.query(deleteProductsQuery, [ids]);
          res.status(200).json({
            message: "Products Deleted successfully",
            admin: deletedProducts.rows[0],
            deletedCount: deletedProducts.rowCount,
          });
        }
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // ------------ Seller API Routes End ----------------//

    // ------------ Users API Routes ----------------//

    /** Google OAuth Routes **/

    app.post("/token/refresh", (req, res) => {
      const refreshToken = req.cookies.RefreshToken;
      if (!refreshToken) return res.sendStatus(401);

      try {
        const payload = jwt.verify(
          refreshToken,
          process.env.REFRESH_TOKEN_SECRET,
        );
        const newAccessToken = jwt.sign(
          { id: payload.id, email: payload.email, role: payload.role },
          process.env.JWT_SECRET_KEY,
          { expiresIn: "7d" },
        );

        res
          .clearCookie("Token", {
            httpOnly: true,
            secure: true,
            sameSite: "None",
            domain: ".bazarigo.com",
            path: "/",
            maxAge: 0,
          })
          .clearCookie("RefreshToken", {
            httpOnly: true,
            secure: true,
            sameSite: "None",
            domain: ".bazarigo.com",
            path: "/",
            maxAge: 0,
          });

        res.cookie("Token", newAccessToken, {
          httpOnly: true,
          secure: true,
          sameSite: "None",
          domain: ".bazarigo.com",
          maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
        });

        // Clear old cookies
        // res.clearCookie("Token", {
        //   httpOnly: true,
        //   sameSite: "Strict",
        //   maxAge: 0,
        // });

        // res.clearCookie("RefreshToken", {
        //   httpOnly: true,
        //   sameSite: "Strict",
        //   maxAge: 0,
        // });

        // // Set new access token
        // res.cookie("Token", newAccessToken, {
        //   httpOnly: true,
        //   secure: false,
        //   sameSite: "Strict",
        //   maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
        // });

        res.json({ message: "Access token refreshed" });
      } catch (err) {
        res.sendStatus(403);
      }
    });

    app.get("/auth/google", (req, res, next) => {
      passport.authenticate("google", {
        scope: ["profile", "email"],
        state: req.query?.state || "/",
      })(req, res, next);
    });

    app.get(
      "/auth/google/callback",
      passport.authenticate("google", {
        session: false,
        failureRedirect: `${process.env.BASEURL}/sign-up`,
      }),
      (req, res) => {
        const redirectPath = req.query.state || "/";
        const payload = {
          id: req.user.id,
          email: req.user.email,
          role: req.user.role,
        };
        const accessToken = jwt.sign(payload, process.env.JWT_SECRET_KEY, {
          expiresIn: "30m",
        });
        const refreshToken = jwt.sign(
          payload,
          process.env.REFRESH_TOKEN_SECRET,
          {
            expiresIn: "30d", // long-lived token
          },
        );

        res
          .cookie("Token", accessToken, {
            httpOnly: true,
            secure: true,
            sameSite: "None",
            domain: ".bazarigo.com",
            maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
          })
          .cookie("RefreshToken", refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: "None",
            domain: ".bazarigo.com",
            maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
          })
          .redirect(`${process.env.BASEURL}${redirectPath}`);

        // Set new access token
        // res
        //   .cookie("Token", accessToken, {
        //     httpOnly: true,
        //     secure: false,
        //     sameSite: "Strict",
        //     maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
        //   })
        //   .cookie("RefreshToken", refreshToken, {
        //     httpOnly: true,
        //     secure: false,
        //     sameSite: "Strict",
        //     maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
        //   })
        //   .redirect(`${process.env.BASEURL}${redirectPath}`);
      },
    );
    // POST: Create Users API Route

    app.post("/create-user", upload.single("profileImg"), async (req, res) => {
      try {
        const userInfo = req.body;
        const file = req.file;
        const id = uuidv4();

        // Email validation
        if (!emailRegex.test(userInfo.email)) {
          return res.status(400).json({ message: "Invalid email format" });
        }

        // Password validation
        if (!passwordRegex.test(userInfo.password)) {
          return res.status(400).json({
            message: "Password must be min 8 chars with letters & numbers",
          });
        }

        // Check if user already exists
        const checkUser = await pool.query(
          `
    SELECT email FROM users WHERE email=$1
    UNION
    SELECT email FROM sellers WHERE email=$1
    UNION
    SELECT email FROM admins WHERE email=$1
  `,
          [userInfo.email],
        );

        if (checkUser.rows.length > 0) {
          return res.status(400).json({ message: "User Already Exists" });
        }

        // Handle profile image
        let profile_imgPath = null;
        if (file) {
          const uploadDir = path.join(
            __dirname,
            "uploads",
            "users",
            `${userInfo.name}`,
          );
          if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
          }

          const safeName = (userInfo.name || "user").replace(/\s+/g, "_");
          const filename = `${safeName}_profile_${uuidv4()}.webp`;
          const filepath = path.join(uploadDir, filename);
          await sharp(file.buffer).webp({ lossless: true }).toFile(filepath);
          profile_imgPath = `/uploads/users/${userInfo.name}/${filename}`;
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(userInfo.password, 12);

        // Generate username
        const userName = await generateUsername(userInfo.email, pool);

        const query = `INSERT INTO users (
      id, name, user_name, email, img, phone, password,
      address, district, thana, postal_code, created_at, updated_at,
      date_of_birth, gender
    ) VALUES (
      $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW(), $12, $13
    ) RETURNING *;`;

        const values = [
          id,
          userInfo.name,
          userName,
          userInfo.email,
          profile_imgPath || null,
          userInfo.phone || null,
          hashedPassword,
          userInfo.address || null,
          userInfo.district || null,
          userInfo.thana || null,
          userInfo.postal_code || null,
          userInfo.date_of_birth || null,
          userInfo.gender || null,
        ];

        const insertedUser = await pool.query(query, values);

        res.status(201).json({
          message: "User created successfully",

          createdCount: insertedUser.rowCount,
        });
      } catch (error) {
        res
          .status(500)
          .json({ message: "Internal server error", error: error.message });
      }
    });
    app.post("/register", upload.single("profileImg"), async (req, res) => {
      try {
        const userInfo = req.body;
        const file = req.file;

        // Email validation
        if (!emailRegex.test(userInfo.email)) {
          return res.status(400).json({ message: "Invalid email format" });
        }

        // Password validation
        if (!passwordRegex.test(userInfo.password)) {
          return res.status(400).json({
            message: "Password must be min 8 chars with letters & numbers",
          });
        }

        // Check if user already exists
        const checkUser = await pool.query(
          `
    SELECT email FROM users WHERE email=$1
    UNION
    SELECT email FROM sellers WHERE email=$1
    UNION
    SELECT email FROM admins WHERE email=$1
  `,
          [userInfo.email],
        );
        if (checkUser.rows.length > 0) {
          return res.status(400).json({ message: "User Already Exists" });
        }

        // Handle profile image
        let profile_imgPath = null;
        if (file) {
          const uploadDir = path.join(
            __dirname,
            "uploads",
            "users",
            `${userInfo.name}`,
          );
          if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
          }

          const safeName = (userInfo.name || "user").replace(/\s+/g, "_");
          const filename = `${safeName}_profile_${uuidv4()}.webp`;
          const filepath = path.join(uploadDir, filename);
          await sharp(file.buffer).webp({ lossless: true }).toFile(filepath);
          profile_imgPath = `/uploads/users/${userInfo.name}/${filename}`;
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(userInfo.password, 12);

        // Generate username
        const userName = await generateUsername(userInfo.email, pool);

        // Prepare temp_data JSON
        const tempData = {
          name: userInfo.name,
          user_name: userName,
          email: userInfo.email,
          phone: userInfo.phone,
          password: hashedPassword,
          img: profile_imgPath,
          address: userInfo.address,
          district: userInfo.district,
          thana: userInfo.thana,
          postal_code: userInfo.postal_code,
          date_of_birth: userInfo.date_of_birth,
          gender: userInfo.gender,
        };

        // ✅ Generate OTP
        const otp = crypto.randomInt(100000, 999999).toString();
        const expiresAt = new Date(Date.now() + 1 * 60 * 1000); // 1 minutes

        // Remove old OTP if exists
        await pool.query("DELETE FROM email_otps WHERE email=$1", [
          userInfo.email,
        ]);

        // Save OTP + temp_data
        await pool.query(
          "INSERT INTO email_otps (email, otp, expires_at, temp_data) VALUES ($1,$2,$3,$4)",
          [userInfo.email, otp, expiresAt, JSON.stringify(tempData)],
        );

        // Send OTP email
        await sendEmail(
          userInfo.email,
          "Your OTP for Bazarigo Registration",
          `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 10px; background-color: #f9f9f9;">
  <h2 style="color: #FF0055; text-align: center;">Bazarigo</h2>
  <p>Hi there,</p>
  <p>Use the following One-Time Password (OTP) to complete your <strong>User Registration</strong> on Bazaarigo. This OTP is valid for <strong>1 minutes</strong>.</p>
  <p style="text-align: center; margin: 30px 0;">
    <span style="font-size: 28px; font-weight: bold; letter-spacing: 4px; color: #FF0055;">${otp}</span>
  </p>
  <p>If you did not request this, please ignore this email.</p>
  <hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">
  <p style="font-size: 12px; color: #777; text-align: center;">
    &copy; ${new Date().getFullYear()} Bazaarigo. All rights reserved.
  </p>
</div>
`,
        );

        return res
          .status(200)
          .json({ message: "OTP sent to your email", otp_required: true });
      } catch (error) {
        res
          .status(500)
          .json({ message: "Internal server error", error: error.message });
      }
    });

    app.post("/login", async (req, res) => {
      try {
        const { email, password, rememberMe } = req.body;

        let user = null;
        let role = null;

        // 1️⃣ Check Admins Table
        let result = await pool.query("SELECT * FROM admins WHERE email=$1;", [
          email,
        ]);
        if (result.rows.length > 0) {
          user = result.rows[0];
          role = user.role || "moderator";
        }

        // 2️⃣ If not admin → Check Sellers Table
        if (!user) {
          result = await pool.query("SELECT * FROM sellers WHERE email=$1;", [
            email,
          ]);
          if (result.rows.length > 0) {
            user = result.rows[0];
            role = user.role || "seller";
          }
        }

        // 3️⃣ If not seller → Check Users Table
        if (!user) {
          result = await pool.query("SELECT * FROM users WHERE email=$1;", [
            email,
          ]);
          if (result.rows.length > 0) {
            user = result.rows[0];
            role = user.role || "customer";
          }
        }

        // ❌ No user found
        if (!user) return res.status(400).json({ message: "User not found" });
        // ❌ Check is_active
        if (user) {
          if (
            user.is_active === false &&
            (role === "customer" || role === "seller")
          ) {
            return res.status(403).json({ message: "Account suspended" });
          }

          if (
            user.is_active === false &&
            (role === "admin" || role === "super admin")
          ) {
            {
              return res.status(403).json({ message: "Account is Inactive" });
            }
          }
        }

        // ✅ Password check

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid)
          return res.status(400).json({ message: "Invalid password" });

        // ✅ Update last_login
        await pool.query(
          "UPDATE " +
            (role === "admin" || role === "super admin" || role === "moderator"
              ? "admins"
              : role === "seller"
                ? "sellers"
                : "users") +
            " SET last_login=$1 WHERE id=$2;",
          [new Date(), user.id],
        );

        // Generate OTP
        const otp = crypto.randomInt(100000, 999999).toString();
        const expiresAt = new Date(Date.now() + 60 * 1000);

        // Remove old OTP
        await pool.query("DELETE FROM email_otps WHERE email=$1", [email]);

        // Save OTP
        await pool.query(
          "INSERT INTO email_otps (email, otp, expires_at) VALUES ($1,$2,$3)",
          [email, otp, expiresAt],
        );

        // Send OTP email
        await sendEmail(
          email,
          "Your OTP for Bazarigo Login",
          `
  <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 10px; background-color: #f9f9f9;">
    <h2 style="color: #FF0055; text-align: center;">Bazarigo</h2>
    <p>Hi there,</p>
    <p>Use the following One-Time Password (OTP) to login to your Bazaarigo account. This OTP is valid for <strong>1 minute</strong>.</p>
    <p style="text-align: center; margin: 30px 0;">
      <span style="font-size: 28px; font-weight: bold; letter-spacing: 4px; color: #FF0055;">${otp}</span>
    </p>
    <p>If you did not request this, please ignore this email.</p>
    <hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">
    <p style="font-size: 12px; color: #777; text-align: center;">
      &copy; ${new Date().getFullYear()} Bazaarigo. All rights reserved.
    </p>
  </div>
  `,
        );

        let token;

        if (rememberMe) {
          token = jwt.sign({ email, password }, process.env.JWT_SECRET_KEY, {
            expiresIn: "30d",
          });
        }

        return res.status(200).json({
          message: "OTP sent to your email",
          otp_required: true,
          token,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // Register Verify
    app.post("/register/verify-otp", async (req, res) => {
      try {
        const { email, otp } = req.body;

        // 1️⃣ Check OTP
        const result = await pool.query(
          "SELECT * FROM email_otps WHERE email=$1 AND otp=$2",
          [email, otp],
        );

        if (result.rows.length === 0)
          return res.status(400).json({ message: "Invalid OTP" });

        const otpData = result.rows[0];

        // 2️⃣ Check expiration
        if (new Date() > otpData.expires_at) {
          await pool.query("DELETE FROM email_otps WHERE email=$1", [email]);
          return res.status(400).json({ message: "OTP expired" });
        }

        // ✅ Delete OTP after successful verification
        await pool.query("DELETE FROM email_otps WHERE email=$1", [email]);

        // 3️⃣ Insert user from temp_data
        const tempData = otpData.temp_data; // JSON object
        const id = uuidv4();

        const query = `INSERT INTO users (
      id, name, user_name, email, img, phone, password,
      address, district, thana, postal_code, created_at, updated_at,
      date_of_birth, gender
    ) VALUES (
      $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW(), $12, $13
    ) RETURNING *;`;

        const values = [
          id,
          tempData.name,
          tempData.user_name,
          tempData.email,
          tempData.img || null,
          tempData.phone || null,
          tempData.password,
          tempData.address || null,
          tempData.district || null,
          tempData.thana || null,
          tempData.postal_code || null,
          tempData.date_of_birth || null,
          tempData.gender || null,
        ];

        const insertedUser = await pool.query(query, values);

        res.status(201).json({
          message: "Registration successful",

          createdCount: insertedUser.rowCount,
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    // Seller Register Verify
    app.post("/register/seller/verify-otp", async (req, res) => {
      try {
        const { email, otp } = req.body;

        // 1️⃣ Check OTP
        const result = await pool.query(
          "SELECT * FROM email_otps WHERE email=$1 AND otp=$2",
          [email, otp],
        );

        if (result.rows.length === 0)
          return res.status(400).json({ message: "Invalid OTP" });

        const otpData = result.rows[0];

        // 2️⃣ Check expiration
        if (new Date() > otpData.expires_at) {
          await pool.query("DELETE FROM email_otps WHERE email=$1", [email]);
          return res.status(400).json({ message: "OTP expired" });
        }

        // ✅ Delete OTP after successful verification
        await pool.query("DELETE FROM email_otps WHERE email=$1", [email]);

        // 3️⃣ Insert seller from temp_data
        const tempData = otpData.temp_data; // JSON object

        const query = `INSERT INTO sellers (
      id, email, user_name, password, full_name, phone_number, img,
      nid_number, store_name, product_category, business_address, district, thana,
      postal_code, trade_license_number, nid_front_file, nid_back_file, bank_name,
      branch_name, account_number, account_holder_name, routing_number, mobile_bank_name,
      mobile_bank_account_number, created_at,  status, date_of_birth, gender
    ) VALUES (
      $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
      $14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,NOW(),$25,$26,$27
    ) RETURNING *;`;

        const values = [
          tempData.id,
          tempData.email,
          tempData.user_name,
          tempData.password,
          tempData.full_Name,
          tempData.phone_number || null,
          tempData.profileImg || null,
          tempData.nidNumber || null,
          tempData.storeName || null,
          tempData.product_category || null,
          tempData.businessAddress || null,
          tempData.district || null,
          tempData.thana || null,
          tempData.postal_code || null,
          tempData.tradeLicenseNumber || null,
          tempData.nidFront || null,
          tempData.nidBack || null,
          tempData.bankName || null,
          tempData.branchName || null,
          tempData.accountNumber || null,
          tempData.accountHolderName || null,
          tempData.routingNumber || null,
          tempData.mobile_bank_name || null,
          tempData.mobileBankAccountNumber || null,
          "pending", // status
          tempData.date_of_birth || null,
          tempData.gender || null,
        ];

        const insertedSeller = await pool.query(query, values);

        if (insertedSeller.rowCount > 0) {
          // Notify admins
          try {
            const admins = await pool.query("SELECT id, role FROM admins");
            await Promise.all(
              admins.rows.map((admin) =>
                createNotification({
                  userId: admin.id,
                  userRole: admin.role,
                  title: "New Seller Request",
                  message: `A new seller "${tempData.full_Name}" has registered and is pending approval.`,
                  type: "seller_request",
                  refId: tempData.id,
                  expiresAt: "30d",
                }),
              ),
            );

            await sendEmail(
              process.env.SUPER_ADMIN,
              "New Seller Application Received",
              `
<div style="font-family: Arial, sans-serif; max-width:600px; margin:auto; padding:25px; border:1px solid #eee; border-radius:10px; background:#fafafa;">
  
  <h2 style="text-align:center; color:#FF0055; margin-bottom:10px;">
    Bazarigo
  </h2>

  <p style="font-size:14px; color:#333;">
    Hello Admin,
  </p>

  <p style="font-size:14px; color:#333;">
    A new seller has submitted a registration request on <strong>Bazarigo</strong>.
  </p>

  <div style="background:#fff; padding:15px; border-radius:8px; border:1px solid #eee; margin:20px 0;">
    <p style="margin:5px 0;"><strong>Name:</strong> ${tempData.full_Name}</p>
    <p style="margin:5px 0;"><strong>Email:</strong> ${tempData.email}</p>
    <p style="margin:5px 0;"><strong>Phone:</strong> ${tempData.phone || "N/A"}</p>
  </div>

  <p style="font-size:14px; color:#333;">
    Please review this seller request from the admin dashboard and approve or reject the application.
  </p>

  <hr style="margin:25px 0; border:none; border-top:1px solid #ddd;" />

  <p style="font-size:12px; color:#777; text-align:center;">
    © ${new Date().getFullYear()} Bazarigo. All rights reserved.
  </p>

</div>
`,
            );
          } catch (notifError) {}

          return res.status(201).json({
            message: "Seller created successfully",
            createdCount: insertedSeller.rowCount,
          });
        }

        res.status(201).json({
          message: "Seller registration successful",
          createdCount: insertedSeller.rowCount,
          seller: insertedSeller.rows[0],
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    // POST verify-otp
    app.post("/verify-otp", async (req, res) => {
      try {
        const { email, otp } = req.body;

        // 1️⃣ Check OTP in DB
        const result = await pool.query(
          "SELECT * FROM email_otps WHERE email=$1 AND otp=$2",
          [email, otp],
        );

        if (result.rows.length === 0)
          return res.status(400).json({ message: "Invalid OTP" });

        const otpData = result.rows[0];

        // 2️⃣ Check expiration
        if (new Date() > otpData.expires_at) {
          // Delete expired OTP
          await pool.query("DELETE FROM email_otps WHERE email=$1", [email]);
          return res.status(400).json({ message: "OTP expired" });
        }

        // ✅ Delete OTP after successful verification
        await pool.query("DELETE FROM email_otps WHERE email=$1", [email]);

        // 3️⃣ Fetch user to generate JWT
        let user = null;
        let role = null;

        let resultUser = await pool.query(
          "SELECT * FROM admins WHERE email=$1",
          [email],
        );
        if (resultUser.rows.length > 0) {
          user = resultUser.rows[0];
          role = user.role || "moderator";
        }

        if (!user) {
          resultUser = await pool.query(
            "SELECT * FROM sellers WHERE email=$1",
            [email],
          );
          if (resultUser.rows.length > 0) {
            user = resultUser.rows[0];
            role = user.role || "seller";
          }
        }

        if (!user) {
          resultUser = await pool.query("SELECT * FROM users WHERE email=$1", [
            email,
          ]);
          if (resultUser.rows.length > 0) {
            user = resultUser.rows[0];
            role = user.role || "customer";
          }
        }

        if (!user) return res.status(400).json({ message: "User not found" });

        // 4️⃣ Generate JWT
        const payload = { id: user.id, email: user.email, role };

        const accessToken = jwt.sign(payload, process.env.JWT_SECRET_KEY, {
          expiresIn: "30m",
        });
        const refreshToken = jwt.sign(
          payload,
          process.env.REFRESH_TOKEN_SECRET,
          {
            expiresIn: "30d", // long-lived token
          },
        );

        res
          .cookie("Token", accessToken, {
            httpOnly: true,
            secure: true,
            sameSite: "None",
            domain: ".bazarigo.com",
            maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
          })
          .cookie("RefreshToken", refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: "None",
            domain: ".bazarigo.com",
            maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
          })
          .status(200)
          .json({
            message: "Login successful",
            login: true,
            role,
          });

        // res
        //   .cookie("Token", accessToken, {
        //     httpOnly: true,
        //     secure: false,
        //     sameSite: "Strict",
        //     maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
        //   })
        //   .cookie("RefreshToken", refreshToken, {
        //     httpOnly: true,
        //     secure: false,
        //     sameSite: "Strict",
        //     maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
        //   })
        //   .status(200)
        //   .json({
        //     message: "Login successful",
        //     login: true,
        //     role,
        //   });
      } catch (err) {
        res.status(500).json({ message: err.message });
      }
    });
    // Resend Otp
    app.post("/resend-otp", async (req, res) => {
      try {
        const { email } = req.body;
        if (!email)
          return res.status(400).json({ message: "Email is required" });

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 60 * 1000);

        // Remove old OTP
        await pool.query("DELETE FROM email_otps WHERE email=$1", [email]);

        // Save OTP
        await pool.query(
          "INSERT INTO email_otps (email, otp, expires_at) VALUES ($1,$2,$3)",
          [email, otp, expiresAt],
        );

        // Send OTP email
        await sendEmail(
          email,
          "Your OTP for Bazarigo Login",
          `
  <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 10px; background-color: #f9f9f9;">
    <h2 style="color: #FF0055; text-align: center;">Bazarigo</h2>
    <p>Hi there,</p>
    <p>Use the following One-Time Password (OTP) to login to your Bazaarigo account. This OTP is valid for <strong>5 minutes</strong>.</p>
    <p style="text-align: center; margin: 30px 0;">
      <span style="font-size: 28px; font-weight: bold; letter-spacing: 4px; color: #FF0055;">${otp}</span>
    </p>
    <p>If you did not request this, please ignore this email.</p>
    <hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">
    <p style="font-size: 12px; color: #777; text-align: center;">
      &copy; ${new Date().getFullYear()} Bazaarigo. All rights reserved.
    </p>
  </div>
  `,
        );
        return res.json({
          message: "OTP resent successfully",
          expires_at: expiresAt,
        });
      } catch (err) {
        console.error(err);
        return res.status(500).json({ message: "Failed to resend OTP" });
      }
    });
    // GET otp
    app.get(
      "/otp",

      async (req, res) => {
        try {
          const { email } = req.query;
          const result = await pool.query(
            `SELECT * FROM email_otps WHERE email=$1`,
            [email],
          );

          res.json(result.rows[0]);
        } catch (err) {
          console.error(err);
          res.status(500).json({ message: err.message });
        }
      },
    );
    // Logout Route
    app.post("/logout", (req, res) => {
      res
        .clearCookie("Token", {
          httpOnly: true,
          secure: true,
          sameSite: "None",
          domain: ".bazarigo.com",
          path: "/",
          maxAge: 0,
        })
        .clearCookie("RefreshToken", {
          httpOnly: true,
          secure: true,
          sameSite: "None",
          domain: ".bazarigo.com",
          path: "/",
          maxAge: 0,
        })
        .status(200)
        .json({
          message: "logout success",
          logOut: true,
        });
      // res
      //   .clearCookie("Token", {
      //     httpOnly: true,
      //     sameSite: "Strict",
      //     maxAge: 0,
      //   })
      //   .clearCookie("RefreshToken", {
      //     httpOnly: true,
      //     sameSite: "Strict",
      //     maxAge: 0,
      //   })
      //   .status(200)
      //   .json({
      //     message: "logout success",
      //     logOut: true,
      //   });
    });

    // Forget Password
    app.post("/forgot-password", async (req, res) => {
      const { email } = req.body;
      const user = await pool.query(
        `
    SELECT id,email,role,'users' AS source FROM users WHERE email=$1
    UNION
    SELECT id,email,role,'sellers' AS source FROM sellers WHERE email=$1
    UNION
    SELECT id,email,role,'admins' AS source FROM admins WHERE email=$1
  `,
        [email],
      );
      if (!user) return res.status(404).json("User not found");

      const token = jwt.sign(user.rows[0], process.env.JWT_SECRET_KEY, {
        expiresIn: "15m",
      });

      const encodedToken = encodeURIComponent(token);
      const link = `${process.env.BASEURL}/change-password?id=${encodedToken}`;

      // Send Reset Link email
      await sendEmail(
        email,
        `Reset Your Bazarigo ${user.rows[0].role} Account Password`,
        `
  <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto;
    padding: 20px; border: 1px solid #eee; border-radius: 10px; background-color: #f9f9f9;">

    <h2 style="color: #FF0055; text-align: center;">Bazarigo</h2>

    <p>Hi there,</p>

    <p>
      We received a request to reset your Bazarigo account password.
      Click the button below to set a new password.
    </p>

    <div style="text-align: center; margin: 30px 0;">
      <a href="${link}"
        style="background-color: #FF0055; color: #ffffff;
        padding: 12px 24px; text-decoration: none;
        border-radius: 6px; font-weight: bold;">
        Reset Password
      </a>
    </div>

    <p>
      This link will expire in <strong>15 minutes</strong>.
      If you did not request this, please ignore this email.
    </p>

    <hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">

    <p style="font-size: 12px; color: #777; text-align: center;">
      &copy; ${new Date().getFullYear()} Bazarigo. All rights reserved.
    </p>
  </div>
  `,
      );

      res.json("Reset link sent");
    });

    // Reset Password
    app.post(
      "/reset-password/:token",

      async (req, res) => {
        const { token } = req.params;
        const { password } = req.body;

        try {
          const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);

          const hashedPassword = await bcrypt.hash(password, 12);

          // // source → users | sellers | admins
          const tableMap = {
            users: "users",
            sellers: "sellers",
            admins: "admins",
          };

          // update query
          const updateResult = await pool.query(
            `UPDATE ${tableMap[decoded.source]} SET password=$1 WHERE id=$2`,
            [hashedPassword, decoded.id],
          );

          res.json({
            message: "Password reset successful",
            updatedCount: updateResult.rowCount,
          });
        } catch (err) {
          console.error(err);
          res.status(400).json({ message: "Invalid or expired token" });
        }
      },
    );

    // PUT: User Settings API Route
    app.put(
      "/users/update/:id",
      upload.single("profileImg"), // profileImg handle
      async (req, res) => {
        try {
          const userId = req.params.id;
          const payload = req.body;
          const file = req.file; // Multer থেকে profile image

          // পুরানো ইউজার fetch
          const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [
            userId,
          ]);
          if (rows.length === 0)
            return res.status(404).json({ message: "User not found" });

          const oldUser = rows[0];

          // Ensure uploads directory exists
          const uploadDir = path.join(__dirname, "uploads", "users");
          if (!fs.existsSync(uploadDir))
            fs.mkdirSync(uploadDir, { recursive: true });

          // Multer buffer → WEBP save
          let profile_imgPath = oldUser.img;
          if (file) {
            const safeName = (payload.full_name || oldUser.name).replace(
              /\s+/g,
              "_",
            );
            const filename = `${safeName}_profile_${uuidv4()}.webp`;
            const filepath = path.join(uploadDir, filename);
            await sharp(file.buffer).webp({ lossless: true }).toFile(filepath);
            profile_imgPath = `/uploads/users/${filename}`;
          }

          // Password হ্যাশ
          let hashedPassword = oldUser.password;
          if (payload.old_password && payload.new_password) {
            const match = await bcrypt.compare(
              payload.old_password,
              oldUser.password,
            );
            if (!match)
              return res
                .status(400)
                .json({ message: "Old password incorrect" });
            hashedPassword = await bcrypt.hash(payload.new_password, 10);
          }

          // Payment methods validation
          let paymentMethods = payload.payment_methods;
          if (typeof paymentMethods === "string") {
            try {
              paymentMethods = JSON.parse(paymentMethods);
            } catch (err) {
              paymentMethods = [];
            }
          }
          if (!paymentMethods || typeof paymentMethods !== "object")
            paymentMethods = [];

          // Update query
          const query = `
        UPDATE users
        SET
          name = $1,
          email = $2,
          password = $3,
          phone = $4,
          date_of_birth = $5,
          gender = $6,
          img = $7,
          address = $8,
          district = $9,
          thana = $10,
          postal_code = $11,
          updated_at = NOW(),
          payment_methods = $12
        WHERE id = $13
        RETURNING *;
      `;

          const values = [
            payload.full_name || oldUser.name,
            payload.email || oldUser.email,
            hashedPassword,
            payload.phone || oldUser.phone,
            payload.date_of_birth || oldUser.date_of_birth,
            payload.gender || oldUser.gender,
            profile_imgPath,
            payload.address || oldUser.address,
            payload.district || oldUser.district,
            payload.thana || oldUser.thana,
            payload.postal_code || oldUser.postal_code,
            JSON.stringify(paymentMethods),
            userId,
          ];

          const result = await pool.query(query, values);

          // Orders update (যদি user previous orders থাকে)
          if (result.rowCount > 0) {
            const ordersResult = await pool.query(
              `SELECT * FROM orders WHERE customer_id = $1`,
              [userId],
            );
            if (ordersResult.rows.length > 0) {
              await pool.query(
                `UPDATE orders SET customer_name = $1, customer_email = $2 WHERE customer_id = $3`,
                [
                  payload.full_name || oldUser.name,
                  payload.email || oldUser.email,
                  userId,
                ],
              );
            }

            return res.status(200).json({
              message: "User updated successfully",
              updatedCount: result.rowCount,
            });
          }
        } catch (error) {
          if (error.code === "23505" && error.detail.includes("email")) {
            return res.status(400).json({ message: "Email already exists" });
          }
          res.status(500).json({ message: "Internal server error" });
        }
      },
    );

    // GET: Get Users API Route
    app.get(
      "/users",
      passport.authenticate("jwt", { session: false }),
      verifyAdmin,
      async (req, res) => {
        try {
          const query = `
         SELECT 
    u.*,
    COALESCE(c.orders_count, 0) AS orders_count,
    COALESCE(r.recent_orders, '[]'::jsonb) AS recent_orders
FROM users u
LEFT JOIN (
    SELECT 
        customer_email, 
        COUNT(*) AS orders_count
    FROM orders
    GROUP BY customer_email
) c ON u.email = c.customer_email
LEFT JOIN (
    SELECT 
        customer_email,
        jsonb_agg(
            jsonb_build_object(
                'order_id', order_id,
                'order_number', order_number,
                'order_date', order_date,
                'total', total,
                'delivery_charge', delivery_cost,       -- added delivery charge
                'payment_status', payment_status,
                'products', order_items->0->'productinfo'  -- all products in that order
            )
            ORDER BY order_date DESC
        ) AS recent_orders
    FROM (
        SELECT *,
               ROW_NUMBER() OVER (
                   PARTITION BY customer_email
                   ORDER BY order_date DESC
               ) AS rn
        FROM orders
    ) t
    WHERE rn <= 2   -- only last 2 orders
    GROUP BY customer_email
) r ON u.email = r.customer_email;



          `;

          const result = await pool.query(query);
          res.status(200).json({
            message: "Users route is working!",
            users: result.rows,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    app.get(
      "/user",
      passport.authenticate("jwt", { session: false }),
      async (req, res) => {
        try {
          const userId = req.user.id;
          const role = req.user.role; // JWT থেকে role নাও
          let table;
          if (
            role === "admin" ||
            role === "super admin" ||
            role === "moderator"
          )
            table = "admins";
          else if (role === "seller") table = "sellers";
          else table = "users";

          const query = `SELECT * FROM ${table} WHERE id=$1;`;
          const result = await pool.query(query, [userId]);

          if (result.rows.length === 0) {
            return res.status(404).json({ message: `${role} not found` });
          }

          res.status(200).json({
            message: `${role} route is working!`,
            user: result.rows[0],
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // Delete: Delete Users Bulk API Route
    app.delete("/users/bulk-delete", async (req, res) => {
      try {
        const { ids } = req.body; // expect an array of user IDs

        if (!Array.isArray(ids) || ids.length === 0) {
          return res.status(400).json({
            message: "Invalid request: 'ids' must be a non-empty array",
          });
        }
        const query = "DELETE FROM users WHERE id = ANY($1);";
        const result = await pool.query(query, [ids]);
        if (result.rowCount > 0) {
          const deleteOrdersQuery = `
  DELETE FROM orders WHERE customer_id = ANY($1);
    
  `;
          const deletedOrders = await pool.query(deleteOrdersQuery, [ids]);
          res.status(200).json({
            message: "Orders Deleted successfully",

            deletedCount: deletedOrders.rowCount,
          });
        }

        res.status(200).json({
          message: "Users Bulk Delete route is working!",
          deletedCount: result.rowCount,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // ------------ Users API Routes End ----------------//

    // ------------ Wishlist API Routes ----------------//

    // POST: Create Wishlist API Route
    app.post("/wishlist", async (req, res) => {
      try {
        const {
          email,
          product_Id,
          product_name,
          sale_price,
          product_img,
          product_category,
          regular_price,
          variants,
          weight,
          brand,
          qty,
        } = req.body;

        const checkQuery =
          "SELECT * FROM wishlist WHERE user_email=$1 AND product_id=$2";
        const checkResult = await pool.query(checkQuery, [email, product_Id]);

        if (checkResult.rows.length === 0) {
          const wishlistId = uuidv4();
          const insertQuery =
            "INSERT INTO wishlist (wishlist_id, user_email, product_id, product_name, sale_price,regular_price,variants,weight,brand,qty,product_category,img) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)";
          const values = [
            wishlistId,
            email,
            product_Id,
            product_name,
            sale_price,
            regular_price,
            variants,
            weight,
            brand,
            qty,
            product_category,
            product_img,
          ];
          const createResult = await pool.query(insertQuery, values);

          return res.status(201).json({
            message: "Wishlist Item Added!",
            createdCount: createResult.rowCount,
          });
        } else {
          const deleteQuery =
            "DELETE FROM wishlist WHERE user_email=$1 AND product_id=$2";
          const deleteResult = await pool.query(deleteQuery, [
            email,
            product_Id,
          ]);
          return res.status(200).json({ deletedCount: deleteResult.rowCount });
        }
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // GET: GET WishlistItems By Email API Route
    app.get(
      "/wishlist",
      passport.authenticate("jwt", { session: false }),

      async (req, res) => {
        try {
          const { email, id } = req.query;
          if (email !== req.user.email) {
            return res.status(401).send("unauthorized access");
          }
          if (id === undefined) {
            const query = "SELECT * FROM wishlist WHERE user_email=$1;";
            const result = await pool.query(query, [email]);

            return res.status(200).json({
              message: "Wishlist route is working!",
              wishlists: result.rows,
            });
          }
          const query =
            "SELECT * FROM wishlist WHERE user_email=$1 AND product_id=$2;";
          const result = await pool.query(query, [email, id]);

          return res.status(200).json({
            message: "Check Is In Wishlist !",
            isInWishlist: result.rows.length > 0,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // DELETE: Delete WishlistItems By ID API Route
    app.delete("/wishlist/:id", async (req, res) => {
      try {
        const { id } = req.params;
        const deleteQuery = "DELETE FROM wishlist WHERE wishlist_id=$1;";
        const deleteResult = await pool.query(deleteQuery, [id]);

        res.status(200).json({
          message: "Wishlist Item Deleted!",
          deletedCount: deleteResult.rowCount,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // ------------ Wishlist API Routes End -------------//

    // ------------ Following List API Routes -----------//
    //POST: Create Following API Route
    app.post("/following", async (req, res) => {
      try {
        const { userId, sellerId, sellerRole } = req.body;

        if (!userId || !sellerId) {
          return res.status(400).json({
            message: "user_id and seller_id and seller role required",
          });
        }

        // 1️⃣ আগেই আছে কিনা চেক
        const checkQuery = `
      SELECT * FROM following
      WHERE user_id = $1 AND seller_id = $2
    `;
        const checkResult = await pool.query(checkQuery, [userId, sellerId]);

        // 2️⃣ যদি থাকে → delete = unfollow
        if (checkResult.rowCount > 0) {
          const deleteQuery = `
        DELETE FROM following
        WHERE user_id = $1 AND seller_id = $2
      `;
          const deleteResult = await pool.query(deleteQuery, [
            userId,
            sellerId,
          ]);

          return res.json({
            message: "Unfollowed successfully",
            status: "unfollow",
            deletedCount: deleteResult.rowCount,
          });
        }

        // 3️⃣ না থাকলে → insert = follow
        const insertQuery = `
      INSERT INTO following (user_id, seller_id)
      VALUES ($1, $2)
      RETURNING *;
    `;
        const insertResult = await pool.query(insertQuery, [userId, sellerId]);

        if (insertResult.rowCount > 0) {
          await createNotification({
            userId: sellerId,
            userRole: sellerRole,
            title: "New Follower",
            message: `You have a new follower!`,
            type: "status",
            refId: userId,
            expiresAt: "7d",
          });
          return res.status(201).json({
            message: "Followed successfully",
            status: "follow",
            createdCount: insertResult.rowCount,
          });
        }
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error" });
      }
    });

    //GET: Check Following Status API Route

    app.get(
      "/following/check/:userId/:sellerId",
      passport.authenticate("jwt", { session: false }),

      async (req, res) => {
        try {
          const { userId, sellerId } = req.params;

          const query = `
      SELECT * FROM following
      WHERE user_id = $1 AND seller_id = $2
    `;
          const result = await pool.query(query, [userId, sellerId]);

          res.json({
            isFollowing: result.rowCount > 0,
          });
        } catch (err) {
          console.error(err);
          res.status(500).json({ message: "Server error" });
        }
      },
    );

    // GET: Get Following List By User ID API Route
    app.get(
      "/following/:userId",
      passport.authenticate("jwt", { session: false }),

      async (req, res) => {
        try {
          const { userId } = req.params;
          if (userId !== req.user.id) {
            return res.status(401).send("unauthorized access");
          }
          if (!userId) {
            return res.status(400).json({ message: "userId required" });
          }

          const query = `
      SELECT
  f.user_id,

  COALESCE(s.id, a.id) AS seller_id,
  COALESCE(s.store_name, a.store_name) AS seller_store_name,
  COALESCE(s.full_name, a.full_name) AS seller_full_name,
  COALESCE(s.email, a.email) AS seller_email,

  CASE
    WHEN s.id IS NOT NULL THEN 'seller'
    WHEN a.id IS NOT NULL THEN 'admin'
  END AS seller_type

FROM following f
LEFT JOIN sellers s ON f.seller_id = s.id
LEFT JOIN admins a ON f.seller_id = a.id

WHERE f.user_id = $1
ORDER BY f.followed_at DESC;

    `;

          const result = await pool.query(query, [userId]);

          res.json({
            sellers: result.rows,
          });
        } catch (err) {
          console.error(err);
          res.status(500).json({ message: "Server error" });
        }
      },
    );

    // ----------- Following List API Routes End -------//

    // ------------ Cart API Routes ----------------//

    // POST: Create Cart API Route
    app.post("/carts", async (req, res) => {
      try {
        const { email } = req.query;
        const cartId = uuidv4();
        const { sellerId, productInfo, deliveries } = req.body;

        const existingQuery =
          "SELECT * FROM carts WHERE user_email=$1 AND sellerId=$2";

        const existingCartResult = await pool.query(existingQuery, [
          email,
          sellerId,
        ]);

        if (existingCartResult.rowCount > 0) {
          const existingCart = existingCartResult.rows[0];

          // ✅ define existingProducts properly
          const existingProducts = existingCart.productinfo;
          const existingProductIds = existingProducts.map((p) => p.product_Id);

          const newProducts = productInfo.filter(
            (p) => !existingProductIds.includes(p.product_Id),
          );

          if (newProducts.length === 0) {
            return res
              .status(200)
              .json({ message: "Product already in cart!" });
          }

          const updatedCart = [...existingProducts, ...newProducts];
          const updateCartQuery = `
        UPDATE carts
        SET productInfo = $1
        WHERE cart_id = $2
      `;
          const updateCartResult = await pool.query(updateCartQuery, [
            JSON.stringify(updatedCart),
            existingCart.cart_id,
          ]);

          res.status(200).json({
            message: "Cart updated successfully!",
            updatedCount: updateCartResult.rowCount,
          });
        } else {
          const insertCartQuery = `
        INSERT INTO carts (cart_id,user_email,sellerId,productInfo,deliveries)
        VALUES ($1,$2,$3,$4,$5);
      `;
          const insertCartQueryValues = [
            cartId,
            email,
            sellerId,
            JSON.stringify(productInfo),
            deliveries,
          ];
          const insertCartResult = await pool.query(
            insertCartQuery,
            insertCartQueryValues,
          );

          res.status(201).json({
            message: "Cart created successfully!",
            createdCount: insertCartResult.rowCount,
          });
        }
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    app.get(
      "/carts",
      passport.authenticate("jwt", { session: false }),

      async (req, res) => {
        try {
          const { email } = req.query;
          if (email !== req.user.email) {
            return res.status(401).send("unauthorized access");
          }

          const query = `
      SELECT 
    c.*,
    COALESCE(s.full_name, a.full_name) AS seller_name,
    COALESCE(s.store_name, a.store_name) AS seller_store_name,
    COALESCE(s.role, a.role) AS seller_role,
    jsonb_array_length(c.productinfo) AS product_count
FROM carts c
LEFT JOIN sellers s ON c.sellerid = s.id
LEFT JOIN admins a ON c.sellerid = a.id
WHERE c.user_email = $1;

    `;

          const result = await pool.query(query, [email]);

          res.status(200).json({
            message: "Carts route is working!",
            carts: result.rows,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // PATCH Add deliveries
    app.patch("/carts", async (req, res) => {
      try {
        const { deliveries, cartId } = req.body;

        const query =
          "UPDATE carts SET deliveries = $1 WHERE cart_id = $2 RETURNING *";
        const values = [JSON.stringify(deliveries), cartId];
        const updateResult = await pool.query(query, values);

        res.status(200).json({
          message: "Quantity updated successfully!",
          updatedCount: updateResult.rowCount,
        });
      } catch (error) {
        console.error("Error updating quantity:", error);
        res.status(500).json({ message: error.message });
      }
    });

    // ✅ PATCH route for updating quantity inside JSONB productInfo
    app.patch("/carts/update-qty", async (req, res) => {
      try {
        const { cartId, productId, newQty } = req.body;

        if (!cartId || !productId || typeof newQty !== "number" || newQty < 1) {
          return res.status(400).json({ message: "Invalid data" });
        }

        // Step 1: Get current cart data
        const selectQuery = "SELECT productinfo FROM carts WHERE cart_id = $1";
        const cartResult = await pool.query(selectQuery, [cartId]);

        if (cartResult.rowCount === 0) {
          return res.status(404).json({ message: "Cart not found" });
        }

        const productInfo = cartResult.rows[0].productinfo;

        // Step 2: Update qty inside JSON in JS
        const updatedInfo = productInfo.map((item) =>
          item.product_Id === productId ? { ...item, qty: newQty } : item,
        );

        // Step 3: Save updated JSON back to DB
        const updateQuery =
          "UPDATE carts SET productinfo = $1 WHERE cart_id = $2 RETURNING *";
        const updateResult = await pool.query(updateQuery, [
          JSON.stringify(updatedInfo),
          cartId,
        ]);

        res.status(200).json({
          message: "Quantity updated successfully!",
          updatedCount: updateResult.rowCount,
        });
      } catch (error) {
        console.error("Error updating quantity:", error);
        res.status(500).json({ message: error.message });
      }
    });

    app.patch("/carts/remove-product", async (req, res) => {
      try {
        const { cartId, productId } = req.body;

        if (!cartId || !productId) {
          return res.status(400).json({ message: "Invalid data" });
        }

        // Step 1: Fetch current cart
        const selectQuery = "SELECT * FROM carts WHERE cart_id = $1";
        const cartResult = await pool.query(selectQuery, [cartId]);

        if (cartResult.rowCount === 0) {
          return res.status(404).json({ message: "Cart not found" });
        }

        const cart = cartResult.rows[0];
        const productInfo = cart.productinfo;

        // Step 2: Filter out the product to remove
        const updatedInfo = productInfo.filter(
          (item) => item.product_Id !== productId,
        );

        // Step 3: যদি সব প্রোডাক্ট বাদ পড়ে যায় → পুরো cart মুছে ফেল
        if (updatedInfo.length === 0) {
          const deleteQuery = "DELETE FROM carts WHERE cart_id = $1";
          const deletedResult = await pool.query(deleteQuery, [cartId]);
          return res.status(200).json({
            message: "Product removed and cart deleted (empty now).",
            deletedCount: deletedResult.rowCount,
          });
        }

        // Step 4: অন্যথায় শুধু আপডেট করো
        const updateQuery =
          "UPDATE carts SET productinfo = $1 WHERE cart_id = $2 RETURNING *";
        const updateResult = await pool.query(updateQuery, [
          JSON.stringify(updatedInfo),
          cartId,
        ]);

        res.status(200).json({
          message: "Product removed successfully!",

          deletedCount: updateResult.rowCount,
        });
      } catch (error) {
        console.error("Error removing product:", error);
        res.status(500).json({ message: error.message });
      }
    });

    app.delete("/carts", async (req, res) => {
      try {
        const { ids } = req.body; // ডিলিট করার product IDs
        if (!ids || !ids.length) {
          return res.status(400).json({ message: "No IDs provided" });
        }

        // সব কার্ট খুঁজে বের করা
        const cartsResult = await pool.query("SELECT * FROM carts");
        const carts = cartsResult.rows;
        // প্রতিটা কার্টে productinfo আপডেট করা
        for (let cart of carts) {
          let updatedProducts = cart.productinfo.filter(
            (p) => !ids.includes(p.product_Id),
          );

          if (updatedProducts.length === 0) {
            const deleteResult = await pool.query(
              "DELETE FROM carts WHERE cart_id = $1",
              [cart.cart_id],
            );
            res.status(200).json({
              message: "Products deleted successfully",
              deletedCount: deleteResult.rowCount,
            });
          } else {
            const updatedResult = await pool.query(
              "UPDATE carts SET productinfo = $1 WHERE cart_id = $2",
              [JSON.stringify(updatedProducts), cart.cartid],
            );
            res.status(200).json({
              message: "Products deleted successfully",
              updatedCount: updatedResult.rowCount,
            });
          }
        }
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: error.message });
      }
    });

    // ------------ Cart API Routes End----------------//

    // ------------ Zone API Routes ----------------//

    // POST: Create Zone API Route
    app.post("/zones", async (req, res) => {
      try {
        const zoneInfo = req.body;
        const query =
          "INSERT INTO zones (name,delivery_time,delivery_charge) VALUES ($1,$2,$3) RETURNING *;";
        const values = [
          zoneInfo.name,
          zoneInfo.delivery_time,
          zoneInfo.delivery_charge,
        ];
        const result = await pool.query(query, values);
        res.status(201).json({
          message: "Zone created successfully",
          createdCount: result.rowCount,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
    // ADMIN MIDDLEWARE
    // GET: Get Zones API Route
    app.get(
      "/zones",
      passport.authenticate("jwt", { session: false }),
      verifyAdmin,
      async (req, res) => {
        try {
          const query = "SELECT * FROM zones;";
          const result = await pool.query(query);
          res.status(200).json({
            message: "Zones route is working!",
            zones: result.rows,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // POST: Create Postal Zone API Route
    app.post("/postal-zones", async (req, res) => {
      try {
        const postalZoneInfo = req.body;

        const query = `
      INSERT INTO postal_zones
        (postal_code, division, district, thana,place, latitude, longitude, is_remote)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)

      RETURNING *;
    `;

        const values = [
          parseInt(postalZoneInfo.postal_code),
          postalZoneInfo.division,
          postalZoneInfo.district,
          postalZoneInfo.thana,
          postalZoneInfo.place,
          parseFloat(postalZoneInfo.latitude),
          parseFloat(postalZoneInfo.longitude),
          postalZoneInfo.is_remote || false, // default false if not provided
        ];

        const result = await pool.query(query, values);

        res.status(201).json({
          message: "Postal Zone created successfully",
          createdCount: result.rowCount,
          postalZone: result.rows[0],
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // POST: Bulk Create Postal Zones API Route
    app.post("/postal-zones/bulk", async (req, res) => {
      try {
        const postalZones = req.body;

        if (!Array.isArray(postalZones) || postalZones.length === 0) {
          return res
            .status(400)
            .json({ message: "Provide an array of postal zones" });
        }

        const values = [];
        const placeholders = postalZones
          .map((zone, idx) => {
            const baseIndex = idx * 8;
            values.push(
              zone.division,
              zone.district,
              zone.thana,
              zone.place,
              zone.postal_code,
              zone.latitude,
              zone.longitude,
              zone.is_remote || false,
            );
            return `($${baseIndex + 1}, $${baseIndex + 2}, $${
              baseIndex + 3
            }, $${baseIndex + 4}, $${baseIndex + 5}, $${baseIndex + 6}, $${
              baseIndex + 7
            },$${baseIndex + 8})`;
          })
          .join(", ");

        const query = `
      INSERT INTO postal_zones
        (division, district, thana,place, postal_code, latitude, longitude, is_remote)
      VALUES ${placeholders}
      RETURNING *;
    `;

        const result = await pool.query(query, values);

        res.status(201).json({
          message: "Postal Zones created successfully",
          createdCount: result.rowCount,
          postalZones: result.rows,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
    // ADMIN MIDDLEWARE
    // GET: Get Postal Zones API Route
    app.get(
      "/postal-zones",
      passport.authenticate("jwt", { session: false }),
      verifyAdmin,
      async (req, res) => {
        try {
          const query = `SELECT *
FROM postal_zones
ORDER BY
  TRIM(division) ASC,
  TRIM(district) ASC,
  TRIM(thana) ASC;
`;
          const result = await pool.query(query);
          res.status(200).json({
            message: "Postal Zones route is working!",
            postal_zones: result.rows,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );
    // PUT: Update Postal Zones API Route
    app.put("/postal-zones/:id", async (req, res) => {
      try {
        const updatedZone = req.body;
        const { id } = req.params;
        const query = `UPDATE postal_zones
        SET postal_code=$1, division=$2, district=$3, thana=$4,place=$5, latitude=$6, longitude=$7, is_remote=$8
        WHERE id = $9;`;
        const values = [
          parseInt(updatedZone.postal_code),
          updatedZone.division,
          updatedZone.district,
          updatedZone.thana,
          updatedZone.place,
          parseFloat(updatedZone.latitude),
          parseFloat(updatedZone.longitude),
          updatedZone.is_remote,
          id,
        ];

        const result = await pool.query(query, values);

        res.status(200).json({
          message: "Postal Zones Updated!",
          updatedCount: result.rowCount,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
    // DELETE : BULK DELETE
    app.delete("/postal-zones/bulk-delete", async (req, res) => {
      try {
        const { ids } = req.body; // expects array of IDs

        if (!ids || !ids.length)
          return res.status(400).json({ message: "No IDs provided" });

        const query = `DELETE FROM postal_zones WHERE id = ANY($1::int[])`;
        const result = await pool.query(query, [ids]);

        res.status(200).json({ deletedCount: result.rowCount });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
    // DELETE: Remove Postal Zone By Id
    app.delete("/postal-zones/:id", async (req, res) => {
      try {
        const { id } = req.params;
        const query = `DELETE FROM postal_zones WHERE id = $1;`;
        const values = [id];

        const result = await pool.query(query, values);

        res.status(200).json({
          message: "Postal Zones Deleted!",
          deletedCount: result.rowCount,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // ------------ Zone API Routes End ----------------//

    // ------------ Delivery API Routes ----------------//
    // GET: Get Deliveries API Route

    app.get(
      "/deliveries",
      passport.authenticate("jwt", { session: false }),

      async (req, res) => {
        let {
          sellerId,
          userId,
          weight: weightStr,
          orderAmount: orderAmountStr,
          isCod,
        } = req.query;

        const weight = parseInt(weightStr, 10) || 0;
        const orderAmount = parseInt(orderAmountStr, 10) || 0;
        const isCodBool = isCod === "true";

        if (!sellerId || !userId || !weight || !orderAmount) {
          return res.status(400).json({
            error: "sellerId, userId, weight, and orderAmount are required",
          });
        }

        try {
          // 🔹 যদি sellerId admin হয়, তাহলে bazarigo seller এর postal code নাও
          const adminCheck = await pool.query(
            "SELECT role, postal_code FROM admins WHERE id=$1",
            [sellerId],
          );
          let sellerPostalCode = null;

          if (adminCheck.rows.length > 0) {
            if (
              adminCheck.rows[0].role === "admin" ||
              adminCheck.rows[0].role === "moderator"
            ) {
              const bazarigo = await pool.query(
                "SELECT postal_code FROM admins WHERE email='bazarigo.official@gmail.com'",
              );
              sellerPostalCode = bazarigo.rows[0]?.postal_code || "1212"; // default postal code
            } else {
              sellerPostalCode = adminCheck.rows[0].postal_code;
            }
          } else {
            const sellerCheck = await pool.query(
              "SELECT role, postal_code FROM sellers WHERE id=$1",
              [sellerId],
            );

            sellerPostalCode = sellerCheck.rows[0].postal_code;
          }

          const query = `
WITH seller_postal AS (
  SELECT district AS s_district, AVG(latitude) AS s_lat, AVG(longitude) AS s_lon
  FROM postal_zones
  WHERE postal_code = $1
  GROUP BY district
),
customer_postal AS (
  SELECT district AS c_district, AVG(latitude) AS c_lat, AVG(longitude) AS c_lon, MAX(is_remote::int) AS is_remote
  FROM postal_zones
  WHERE postal_code = (SELECT postal_code FROM users WHERE id = $2)
  GROUP BY district
),
distance_calc AS (
  SELECT *,
  6371 * 2 * ASIN(SQRT( POWER(SIN(RADIANS((c_lat - s_lat)/2)),2) + COS(RADIANS(s_lat)) * COS(RADIANS(c_lat)) * POWER(SIN(RADIANS((c_lon - s_lon)/2)),2) )) AS distance_km
  FROM seller_postal sp CROSS JOIN customer_postal cp
),
zone_calc AS (
  SELECT CASE
    WHEN is_remote = 1 THEN 'Remote Area'
    WHEN distance_km <= 20 THEN 'Inside Area'
    WHEN distance_km <= 50 THEN 'Near Area'
    ELSE 'Outside Area'
  END AS zone_name, distance_km
  FROM distance_calc
)
SELECT zc.zone_name, z.delivery_time,
  CAST(
  (
    CASE
      WHEN ($4 * 1.01) >= COALESCE(z.free_delivery_min_amount, 999999)
        THEN 0
      ELSE GREATEST(
        CASE
          WHEN zc.zone_name = 'Inside Area' THEN 70
          WHEN zc.zone_name = 'Near Area' THEN 100
          WHEN zc.zone_name = 'Outside Area' THEN 120
          WHEN zc.zone_name = 'Remote Area' THEN 200
          ELSE 0
        END,
        z.delivery_charge +
        (GREATEST(COALESCE(NULLIF($3, '')::numeric, 1), 0) * 10)
      )
    END
    +
    CASE
      WHEN $5 IS TRUE THEN GREATEST(10, $4 * 0.01)
      ELSE 0
    END
  ) AS INTEGER
) AS total_delivery_charge

FROM zone_calc zc
LEFT JOIN zones z ON z.name = zc.zone_name;
`;

          const result = await pool.query(query, [
            sellerPostalCode, // $1
            userId,
            weight,
            orderAmount,
            isCodBool || false,
          ]);

          if (result.rows.length === 0) {
            return res.status(200).json({
              result: [
                {
                  zone_name: "Inside Area",
                  delivery_time: "1-2 days",
                  total_delivery_charge: 70,
                },
              ],
            });
          }

          return res.status(200).json({ result: result.rows });
        } catch (err) {
          return res.status(500).json({ error: err.message });
        }
      },
    );

    // ------------ Delivery API Routes End ----------------//

    // ------------ Orders API Routes ----------------//
    // POST: Create Order API Route

    app.post("/orders", async (req, res) => {
      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        const { payload, promoCode, userId, paymentPayload } = req.body;
        const orderId = generateId("ODR");

        // Flatten all order items
        const orderdProducts = payload.orderItems.flatMap((item) =>
          item.productinfo.map((prod) => ({
            product_id: prod.product_Id,
            variant_id: prod.variants.id, // সরাসরি variant id
            qty: prod.qty,
            isflashsale: prod.isflashsale,
            sellerid: item.sellerid,
          })),
        );

        // =============================
        // Flash Sale Stock Update
        // =============================
        const updateFlashSaleStock = async (item) => {
          const now = Math.floor(Date.now() / 1000);
          const flashRes = await client.query(
            `SELECT id, sale_products FROM flashSaleProducts WHERE isactive = true AND start_time <= $1 AND end_time >= $1`,
            [now],
          );
          if (!flashRes.rows.length) return;

          const flashSale = flashRes.rows[0];
          let updated = false;

          for (const sp of flashSale.sale_products) {
            if (sp.id !== item.product_id) continue;
            if (!sp.variants?.length) continue;

            const variant = sp.variants.find((v) => v.id === item.variant_id);
            if (!variant) continue;

            variant.stock = Math.max((variant.stock || 0) - item.qty, 0);
            sp.stock = sp.variants.reduce((sum, v) => sum + (v.stock || 0), 0);
            updated = true;
            break;
          }

          if (updated) {
            await client.query(
              `UPDATE flashSaleProducts SET sale_products=$1 WHERE id=$2`,
              [JSON.stringify(flashSale.sale_products), flashSale.id],
            );
          }
        };

        // =============================
        // Normal Product Stock Update + Notifications
        // =============================
        const updateNormalStock = async (item) => {
          const variantRes = await client.query(
            `SELECT id, product_id, stock, regular_price, sale_price FROM product_variants WHERE id=$1`,
            [item.variant_id],
          );
          if (!variantRes.rows.length) return;

          const variant = variantRes.rows[0];
          const newStock = Math.max((variant.stock || 0) - item.qty, 0);

          // Update variant stock
          await client.query(
            `UPDATE product_variants SET stock=$1 WHERE id=$2`,
            [newStock, variant.id],
          );

          // Notification
          const notifications = [];
          if (newStock === 0) notifications.push({ type: "out_of_stock" });
          else if (newStock <= 5) notifications.push({ type: "low_stock" });

          if (notifications.length) {
            const productRes = await client.query(
              `SELECT product_name, seller_id FROM products WHERE id=$1`,
              [variant.product_id],
            );
            const product = productRes.rows[0];

            await Promise.all(
              notifications.map((n) =>
                createNotification({
                  userId: product.seller_id,
                  userRole: "seller",
                  title:
                    n.type === "out_of_stock"
                      ? "Product Out of Stock"
                      : "Low Stock Warning",
                  message: `${product.product_name} (Variant ${variant.id}) ${
                    n.type === "out_of_stock"
                      ? "is now OUT OF STOCK."
                      : "stock is low. Only " + newStock + " left."
                  }`,
                  type: n.type,
                  refId: variant.product_id,
                  expiresAt: "7d",
                }),
              ),
            );
          }

          // Update main product stock = sum of all variants
          const totalStockRes = await client.query(
            `SELECT COALESCE(SUM(stock),0) AS total_stock FROM product_variants WHERE product_id=$1`,
            [variant.product_id],
          );
          const totalStock = totalStockRes.rows[0].total_stock;

          await client.query(`UPDATE products SET stock=$1 WHERE id=$2`, [
            totalStock,
            variant.product_id,
          ]);
        };

        // Update all products concurrently
        await Promise.all(
          orderdProducts.map((item) =>
            item.isflashsale
              ? updateFlashSaleStock(item)
              : updateNormalStock(item),
          ),
        );

        // =============================
        // Insert order
        // =============================
        const query = `
      INSERT INTO orders (
        order_id, order_date, payment_method, payment_status,
        customer_id, customer_name, customer_email, customer_phone,
        customer_address, order_items, subtotal, delivery_cost, total
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
      RETURNING *;
    `;
        const values = [
          orderId,
          payload.orderDate,
          payload.paymentMethod,
          payload.paymentStatus,
          payload.customerId,
          payload.customerName,
          payload.customerEmail,
          payload.customerPhone,
          payload.customerAddress,
          JSON.stringify(payload.orderItems),
          payload.subtotal,
          payload.deliveryCharge,
          payload.total,
        ];
        const result = await client.query(query, values);

        // =============================
        // Promo code
        // =============================
        if (promoCode) {
          const promoRes = await client.query(
            `SELECT id FROM promotions WHERE code=$1`,
            [promoCode],
          );
          if (promoRes.rows.length) {
            await client.query(
              `UPDATE user_promotions SET used=true WHERE user_id=$1 AND promo_id=$2`,
              [userId, promoRes.rows[0].id],
            );
          }
        }

        // =============================
        // Cart cleanup
        // =============================
        const cartPromises = payload.orderItems.map(async (item) => {
          const productIdsToRemove = item.productinfo.map((p) => p.product_Id);
          const updateRes = await client.query(
            `
        UPDATE carts
        SET productinfo = (
          SELECT COALESCE(jsonb_agg(p), '[]'::jsonb)
          FROM jsonb_array_elements(productinfo) p
          WHERE NOT (p->>'product_Id' = ANY($1::text[]))
        )
        WHERE cart_id = $2 AND user_email = $3
        RETURNING productinfo
      `,
            [productIdsToRemove, item.cart_id, item.user_email],
          );

          const remainingProducts = updateRes.rows[0]?.productinfo || [];
          if (!remainingProducts.length) {
            return await client.query(
              `DELETE FROM carts WHERE cart_id=$1 AND user_email=$2`,
              [item.cart_id, item.user_email],
            );
          }
        });

        await Promise.all(cartPromises);

        // =============================
        // Payment
        // =============================
        const paymentId = uuidv4();
        await client.query(
          `INSERT INTO payments (id,order_id,payment_date,amount,payment_method,status,phone_number) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
          [
            paymentId,
            orderId,
            paymentPayload.payment_date,
            paymentPayload.amount,
            paymentPayload.payment_method,
            paymentPayload.payment_status,
            paymentPayload.phoneNumber,
          ],
        );

        // =============================
        // Seller Notifications
        // =============================
        await Promise.all(
          result.rows[0].order_items.map(async (item) => {
            const getSeller = await client.query(
              `
          SELECT id, role FROM admins WHERE id=$1
          UNION
          SELECT id, role FROM sellers WHERE id=$1
        `,
              [item.sellerid],
            );
            const seller = getSeller.rows[0];
            await createNotification({
              userId: seller.id,
              userRole: seller.role,
              title: "New Order",
              message: `You have received a new order`,
              type: "Order",
              refId: result.rows[0].order_id,
              expiresAt: "7d",
            });
          }),
        );

        if (result.rowCount > 0) {
          await sendEmail(
            process.env.SUPER_ADMIN,
            `New Order Received - ${orderId}`,
            `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin:auto; padding:20px; background:#f9f9f9; border-radius:10px;">
  <h2 style="color:#FF0055; text-align:center;">Bazarigo</h2>

  <p><strong>A new order has been placed.</strong></p>

  <table style="width:100%; margin-top:15px;">
    <tr><td><strong>Order ID</strong></td><td>${orderId}</td></tr>
    <tr><td><strong>Customer</strong></td><td>${payload.customerName}</td></tr>
    <tr><td><strong>Email</strong></td><td>${payload.customerEmail}</td></tr>
    <tr><td><strong>Phone</strong></td><td>${payload.customerPhone}</td></tr>
    <tr><td><strong>Total</strong></td><td>৳ ${payload.total}</td></tr>
  </table>

  <p style="margin-top:20px;">Please check admin panel for full details.</p>

  <hr />
  <p style="font-size:12px; text-align:center; color:#777;">
    © ${new Date().getFullYear()} Bazarigo
  </p>
</div>
`,
          );
        }

        await client.query("COMMIT");

        res.status(201).json({
          message: "Order created successfully",
          createdCount: result.rowCount,
        });
      } catch (error) {
        await client.query("ROLLBACK");
        res.status(500).json({ message: error.message });
      } finally {
        client.release();
      }
    });

    // POST: Create Return Requests API Route
    app.post(
      "/return-requests",
      upload.array("images"), // Multer files handle
      async (req, res) => {
        try {
          const {
            orderId,
            reason,
            product_name,
            customer_id,
            customer_email,
            customer_name,
            customer_phone,
          } = req.body;
          const files = req.files; // Multer files

          if (!files || files.length === 0) {
            return res.status(400).json({ message: "No images uploaded" });
          }

          const id = uuidv4();

          const uploadDirs = {
            image: path.join(__dirname, "uploads", "returns", "images"),
            video: path.join(__dirname, "uploads", "returns", "videos"),
          };

          // Create directories if not exist
          for (const dir of Object.values(uploadDirs)) {
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
          }

          const savedPaths = await Promise.all(
            req.files.map(async (file, i) => {
              const mime = file.mimetype;

              if (mime.startsWith("image")) {
                const filename = `${customer_name}-${i}-${uuidv4()}.webp`;
                const filepath = path.join(uploadDirs.image, filename);
                await sharp(file.buffer)
                  .webp({ lossless: true })
                  .toFile(filepath);
                return `/uploads/returns/images/${filename}`;
              } else if (mime.startsWith("video")) {
                const ext = mime.split("/")[1];
                const filename = `${customer_name}-${i}-${uuidv4()}.${ext}`;
                const filepath = path.join(uploadDirs.video, filename);
                await fs.promises.writeFile(filepath, file.buffer);
                return `/uploads/returns/videos/${filename}`;
              }
              return null;
            }),
          );

          // Save uploaded files to WebP
          // const savedPaths = await Promise.all(
          //   files.map(async (file, i) => {
          //     const filename = `${customer_name}-${i}-${uuidv4()}.webp`;
          //     const filepath = path.join(uploadDir, filename);

          //     await sharp(file.buffer)
          //       .webp({ lossless: true })
          //       .toFile(filepath);
          //     return `/uploads/returns/${filename}`;
          //   })
          // );

          const query = `
        INSERT INTO return_requests
          (id, order_id, reason, images, customer_id, customer_email, product_name, customer_name, customer_phone, request_date)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
        RETURNING *;
      `;
          const values = [
            id,
            orderId,
            reason,
            savedPaths,
            customer_id,
            customer_email,
            product_name,
            customer_name,
            customer_phone,
          ];

          const result = await pool.query(query, values);

          if (result.rowCount > 0) {
            const admins = await pool.query("SELECT id, role FROM admins");

            await Promise.all(
              admins.rows.map((admin) =>
                createNotification({
                  userId: admin.id,
                  userRole: admin.role,
                  title: "New Return Request",
                  message: `A return request was submitted for Order ID: ${orderId}`,
                  type: "return_request",
                  refId: orderId,
                  expiresAt: "7d",
                }),
              ),
            );

            return res.status(201).json({
              message: "Return Request submitted successfully",
              createdCount: result.rowCount,
            });
          }
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );
    // ADMIN MIDDLEWARE
    // GET: GET Orders  API Route
    app.get(
      "/orders",
      passport.authenticate("jwt", { session: false }),
      verifyAdmin,
      async (req, res) => {
        try {
          const query = "SELECT * FROM orders;";

          const result = await pool.query(query);
          res.status(200).json({
            message: "orders route is working!",
            orders: result.rows,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // GET: GET Orders By Seller ID
    app.get(
      "/orders/seller/:sellerId",
      passport.authenticate("jwt", { session: false }),
      verifySeller,
      async (req, res) => {
        try {
          const { sellerId } = req.params;
          if (sellerId !== req.user.id) {
            return res.status(401).send("unauthorized access");
          }
          const query = `SELECT 
          *
       FROM orders o
       WHERE EXISTS (
          SELECT 1 FROM jsonb_array_elements(o.order_items) item
          WHERE item->>'sellerid' = $1
       )
    `;
          const result = await pool.query(query, [sellerId]);
          res.status(200).json({
            message: `Orders for seller ${sellerId}`,
            orders: result.rows,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // GET: GET Orders By Email API Route
    app.get(
      "/orders/:email",
      passport.authenticate("jwt", { session: false }),

      async (req, res) => {
        try {
          const { email } = req.params;
          if (email !== req.user.email) {
            return res.status(401).send("unauthorized access");
          }
          const query = `
      SELECT *
FROM orders 
WHERE customer_email = $1;
    `;
          // const query = "SELECT * FROM orders WHERE customer_email=$1;";
          const values = [email];
          const result = await pool.query(query, values);
          res.status(200).json({
            message: "orders route is working!",
            orders: result.rows,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // GET: GET Orders By Email  API Route (Admin)
    app.get(
      "/orders/admin/:email",
      passport.authenticate("jwt", { session: false }),
      verifyAdmin,

      async (req, res) => {
        try {
          const { email } = req.params;

          const query = `
  SELECT COUNT(*) AS order_count
  FROM orders
  WHERE customer_email = $1;
`;
          // const query = "SELECT * FROM orders WHERE customer_email=$1;";
          const values = [email];
          const result = await pool.query(query, values);
          res.status(200).json({
            message: "orders route is working!",
            orders: result.rows[0].order_count,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // Delete: Delete Order Bulk API Route
    app.delete("/orders/bulk-delete", async (req, res) => {
      try {
        const { ids } = req.body; // expects array of IDs

        if (!ids || !ids.length)
          return res.status(400).json({ message: "No IDs provided" });

        const query = `DELETE FROM orders WHERE order_id = ANY($1)`;
        const result = await pool.query(query, [ids]);

        res.status(200).json({ deletedCount: result.rowCount });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
    // PATCH: Update Order Status

    app.patch("/orders/status/:id", async (req, res) => {
      try {
        const { id } = req.params;
        const { order_status, prodId, variantId } = req.body;

        const orderQuery = `SELECT customer_id, order_items FROM orders WHERE order_id=$1`;
        const orderRes = await pool.query(orderQuery, [id]);

        if (!orderRes.rows.length) {
          return res.status(404).json({ message: "Order not found" });
        }

        const orderItems = orderRes.rows[0].order_items;
        const customerId = orderRes.rows[0].customer_id;

        let returnedQty = 0;

        // ----------------------------
        // Returned or Cancelled logic
        // ----------------------------
        if (["Returned", "Cancelled"].includes(order_status)) {
          // Find the product in the order
          const productData = orderItems.flatMap((item) =>
            item.productinfo.filter((p) => p.product_Id === prodId),
          )[0];

          if (!productData) {
            return res
              .status(404)
              .json({ message: "Product not found in the order" });
          }

          returnedQty = productData.qty;

          // Update variant stock directly
          const variantRes = await pool.query(
            `SELECT id, stock, product_id FROM product_variants WHERE id=$1`,
            [variantId || productData.variants.id],
          );
          if (variantRes.rows.length) {
            const variant = variantRes.rows[0];
            const newStock = (variant.stock || 0) + returnedQty;

            await pool.query(
              `UPDATE product_variants SET stock=$1 WHERE id=$2`,
              [newStock, variant.id],
            );

            // Update main product stock = sum of all variants
            const totalStockRes = await pool.query(
              `SELECT COALESCE(SUM(stock),0) AS total_stock FROM product_variants WHERE product_id=$1`,
              [variant.product_id],
            );
            const totalStock = totalStockRes.rows[0].total_stock;
            await pool.query(`UPDATE products SET stock=$1 WHERE id=$2`, [
              totalStock,
              variant.product_id,
            ]);
          }

          // Remove returned/cancelled product from order_items
          const updatedOrderItems = orderItems
            .map((item) => ({
              ...item,
              productinfo: item.productinfo.filter(
                (p) => p.product_Id !== prodId,
              ),
            }))
            .filter((item) => item.productinfo.length > 0);

          if (updatedOrderItems.length > 0) {
            await pool.query(
              `UPDATE orders SET order_items=$1 WHERE order_id=$2`,
              [JSON.stringify(updatedOrderItems), id],
            );
          } else {
            await pool.query(`DELETE FROM orders WHERE order_id=$1`, [id]);
          }

          // Notifications
          await createNotification({
            userId: customerId,
            userRole: "customer",
            title: `Order ${order_status}`,
            message: `A product in your order ${id} has been ${order_status.toLowerCase()}.`,
            type: "order",
            refId: id,
            expiresAt: "7d",
          });

          return res.status(200).json({
            message: `Order ${order_status} successfully`,
            updatedCount: 1,
          });
        }

        // ----------------------------
        // Other statuses (Processing, Shipped, Delivered...)
        // ----------------------------
        const updatedOrderItems = orderItems.map((item) => ({
          ...item,
          productinfo: item.productinfo.map((p) => {
            if (p.product_Id === prodId) p.order_status = order_status;
            return p;
          }),
        }));

        const updatedResult = await pool.query(
          `UPDATE orders SET order_items=$1 WHERE order_id=$2`,
          [JSON.stringify(updatedOrderItems), id],
        );

        if (updatedResult.rowCount > 0) {
          const sellerId =
            updatedOrderItems[0]?.productinfo[0]?.sellerid || null;
          const sellerRole =
            updatedOrderItems[0]?.productinfo[0]?.seller_role || "seller";

          // Customer notification
          await createNotification({
            userId: customerId,
            userRole: "customer",
            title: "Order Update",
            message: `Your order status changed to "${order_status}".`,
            type: "order",
            refId: id,
            expiresAt: "7d",
          });

          // Seller notification
          if (sellerId) {
            await createNotification({
              userId: sellerId,
              userRole: sellerRole,
              title: "Order Update",
              message: `One of your products in order ${id} is now "${order_status}".`,
              type: "order",
              refId: id,
              expiresAt: "7d",
            });
          }

          return res.json({
            message: "Order status updated",
            updatedCount: updatedResult.rowCount,
          });
        }

        res.status(400).json({ message: "No update performed" });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: error.message });
      }
    });

    // PATCH: Update Return Request Status
    app.patch("/return-requests/status/:id", async (req, res) => {
      try {
        const { id } = req.params;
        const { status } = req.body;

        // Validate input
        if (!id) {
          return res
            .status(400)
            .json({ message: "Return request ID is required" });
        }
        if (!status) {
          return res.status(400).json({ message: "Status is required" });
        }

        const isRejected = status.toLowerCase() === "rejected";

        if (isRejected) {
          // Delete return request
          const deleteQuery =
            "DELETE FROM return_requests WHERE id = $1 RETURNING *;";
          const deleteResult = await pool.query(deleteQuery, [id]);

          if (deleteResult.rowCount === 0) {
            return res
              .status(404)
              .json({ message: "Return request not found" });
          }

          const deletedRequest = deleteResult.rows[0];

          // Get user info from order
          const userQuery = `
        SELECT u.id, u.role
        FROM orders o
        JOIN users u ON o.customer_id = u.id
        WHERE o.order_id = $1
      `;
          const userResult = await pool.query(userQuery, [
            deletedRequest.order_id,
          ]);

          if (userResult.rowCount > 0) {
            await createNotification({
              userId: userResult.rows[0].id,
              userRole: userResult.rows[0].role,
              title: "Return Request Rejected",
              message: `A return request was submitted for Order ID: ${deletedRequest.order_id}`,
              type: "return_request",
              refId: deletedRequest.order_id,
              expiresAt: "7d",
            });
          }

          return res.status(200).json({
            message: "Return request rejected and deleted successfully",
            deletedCount: deleteResult.rowCount,
          });
        }

        // Update status for non-rejected requests
        const updateQuery =
          "UPDATE return_requests SET status=$1 WHERE id=$2 RETURNING *;";
        const updateResult = await pool.query(updateQuery, [status, id]);

        if (updateResult.rowCount === 0) {
          return res.status(404).json({ message: "Return request not found" });
        }

        const updatedRequest = updateResult.rows[0];

        // Get user info from order
        const userQuery = `
      SELECT u.id, u.role
      FROM orders o
      JOIN users u ON o.customer_id = u.id
      WHERE o.order_id = $1
    `;
        const userResult = await pool.query(userQuery, [
          updatedRequest.order_id,
        ]);

        if (userResult.rowCount > 0) {
          await createNotification({
            userId: userResult.rows[0].id,
            userRole: userResult.rows[0].role,
            title: "Return Request Approved",
            message: `A return request was submitted for Order ID: ${updatedRequest.order_id}`,
            type: "return_request",
            refId: updatedRequest.order_id,
            expiresAt: "7d",
          });
        }

        return res.status(200).json({
          message: "Return request status updated successfully",
          updatedCount: updateResult.rowCount,
        });
      } catch (error) {
        console.error(error);
        return res.status(500).json({ message: error.message });
      }
    });

    // ADMIN MIDDLEWARE
    // GET: Get Return Order API Route
    app.get(
      "/return-orders",
      passport.authenticate("jwt", { session: false }),
      verifyAdmin,
      async (req, res) => {
        try {
          const query = "SELECT * FROM return_orders;";

          const result = await pool.query(query);
          res.status(200).json({
            message: "Return Order route working successfully",
            returnOrders: result.rows,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );
    // GET: GET Return Orders By Seller ID
    app.get(
      "/return-orders/seller/:sellerId",
      passport.authenticate("jwt", { session: false }),
      verifySeller,
      async (req, res) => {
        try {
          const { sellerId } = req.params;
          if (sellerId !== req.user.id) {
            return res.status(401).send("unauthorized access");
          }
          const query = `SELECT 
          *
       FROM return_orders ro
       WHERE EXISTS (
          SELECT 1 FROM jsonb_array_elements(ro.products) item
          WHERE item->>'sellerid' = $1
       )
    `;
          const result = await pool.query(query, [sellerId]);
          res.status(200).json({
            message: `Return Orders for seller ${sellerId}`,
            returnOrders: result.rows,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );
    // GET: Get Return Order API Route
    app.get(
      "/return-requests",
      passport.authenticate("jwt", { session: false }),
      verifyAdmin,
      async (req, res) => {
        try {
          const query = "SELECT * FROM return_requests WHERE status='pending';";

          const result = await pool.query(query);
          res.status(200).json({
            message: "Return Order route working successfully",
            returnRequests: result.rows,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );
    // GET: Get Return Order By email API Route
    app.get(
      "/return-requests-user/:email",
      passport.authenticate("jwt", { session: false }),
      async (req, res) => {
        try {
          const email = req.params.email;
          if (email !== req.user.email) {
            return res.status(401).send("unauthorized access");
          }
          const query =
            "SELECT * FROM return_requests WHERE customer_email=$1;";
          const values = [email];
          const result = await pool.query(query, values);
          res.status(200).json({
            message: "Return Order route working successfully",
            returnRequests: result.rows,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // DELETE: Delete Return Request By Id  API Route
    app.delete("/return-requests/:id", async (req, res) => {
      try {
        const returnRequestId = req.params.id;
        const query = "DELETE FROM return_requests WHERE id = $1;";
        const values = [returnRequestId];
        const result = await pool.query(query, values);

        res.status(200).json({
          message: `Return Request deleted successfully for ID: ${returnRequestId}`,
          deletedCount: result.rowCount,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // DELETE: Delete Return Order By id API Route
    app.delete(
      "/return-orders/delete/:id",
      passport.authenticate("jwt", { session: false }),
      verifyAdmin,
      async (req, res) => {
        try {
          const { id } = req.params;
          const query = "DELETE FROM return_orders WHERE id =$1;";

          const result = await pool.query(query, [id]);
          res.status(200).json({
            message: "Return Order route working successfully",
            deletedCount: result.rowCount,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // ------------ Orders API Routes End ----------------//

    // ------------ Payments API Routes ----------------//

    // GET: GET Payments API Route
    app.get(
      "/payments",
      passport.authenticate("jwt", { session: false }),
      verifyAdmin,
      async (req, res) => {
        try {
          const query = "SELECT * FROM payments ORDER BY status DESC;";

          const result = await pool.query(query);
          res.status(200).json({
            message: "Payment return successfully",
            payments: result.rows,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    app.get(
      "/seller-payments",
      passport.authenticate("jwt", { session: false }),
      verifyAdmin,
      async (req, res) => {
        try {
          const query =
            "SELECT * FROM sellerpayments ORDER BY payment_date DESC";

          const result = await pool.query(query);
          res.status(200).json({
            message: "Payment return successfully",
            payments: result.rows,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    app.get(
      "/seller-payments/:sellerId",
      passport.authenticate("jwt", { session: false }),
      verifySeller,
      async (req, res) => {
        try {
          const { sellerId } = req.params;
          if (sellerId !== req.user.id) {
            return res.status(401).send("unauthorized access");
          }
          const query =
            "SELECT * FROM sellerpayments WHERE seller_id=$1 ORDER BY status DESC;";

          const result = await pool.query(query, [sellerId]);
          res.status(200).json({
            message: "Payment return successfully",
            payments: result.rows,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // PATCH: Update Payment status API Route
    app.patch("/payments/:id", async (req, res) => {
      try {
        const paymentId = req.params.id;
        const { status, orderId } = req.body;
        const query = "UPDATE payments SET status=$1 WHERE id = $2;";
        const values = [status, paymentId];
        const result = await pool.query(query, values);

        if (result.rowCount > 0) {
          const getOrderQuery =
            "UPDATE orders SET payment_status=$1 WHERE order_id = $2;";
          const orderResult = await pool.query(getOrderQuery, [
            status,
            orderId,
          ]);
          return res.status(200).json({
            message: `Payment status updated successfully for ID: ${paymentId}`,
            updatedCount: orderResult.rowCount,
          });
        }
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // POST: Create Seller Payments API Route
    app.post(
      "/seller-payments",
      passport.authenticate("jwt", { session: false }),
      verifyAdmin,
      async (req, res) => {
        try {
          const {
            seller_id,
            seller_name,
            seller_store_name,
            amount,
            payment_method,
            payment_date,
            mobile_bank_name,
            transaction_id,
            mobile_bank_account_number,
            bank_name,
            bank_account_holder_name,
            bank_account_number,
          } = req.body;

          const query = `
      INSERT INTO sellerpayments
      (seller_id, seller_name, seller_store_name, amount, payment_method, mobile_bank_name, transaction_id, mobile_bank_account_number, bank_name, bank_account_holder_name, bank_account_number, payment_date,status,created_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW())
      RETURNING *
    `;

          const values = [
            seller_id,
            seller_name,
            seller_store_name,
            amount,
            payment_method,
            mobile_bank_name || null,
            transaction_id || null,
            mobile_bank_account_number || null,
            bank_name || null,
            bank_account_holder_name || null,
            bank_account_number || null,
            payment_date,
            "pending",
          ];

          const result = await pool.query(query, values);

          if (result.rowCount > 0) {
            await createNotification({
              userId: seller_id,
              userRole: "seller",
              title: "New Payment Received",
              message: `You have received a new payment from Admin.`,
              type: "Payment",
              refId: req.user.id, // reference to who sent the message
              expiresAt: "7d",
            });
          }

          res.status(201).json({
            message: "Payment saved successfully",
            payment: result.rows[0],
          });
        } catch (error) {
          console.error(error);
          res
            .status(500)
            .json({ message: "Server error", error: error.message });
        }
      },
    );

    // ------------ Payments API Routes End----------------//

    // ------------ Promotions API Routes------------//

    // POST: Create Promotions API Route
    app.post("/promotions", async (req, res) => {
      try {
        const { code, discount, start_date, end_date } = req.body;

        const query =
          "INSERT INTO promotions (code, discount, start_date, end_date,is_active) VALUES ($1,$2,$3,$4,$5) RETURNING *;";
        const values = [code, parseInt(discount), start_date, end_date, false];
        const result = await pool.query(query, values);

        res.status(201).json({
          message: "Promotion created successfully",
          createdCount: result.rowCount,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // GET: GET Promotions API Route
    app.get(
      "/promotions",
      passport.authenticate("jwt", { session: false }),
      verifyAdmin,
      async (req, res) => {
        try {
          const query = "SELECT * FROM promotions ;";

          const result = await pool.query(query);
          res.status(200).json({
            message: "Promotions return successfully",
            promotions: result.rows,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // PATCH: Update Payment status API Route
    app.patch("/promotions/:id", async (req, res) => {
      try {
        const promotionId = req.params.id;
        const { is_active } = req.body;
        const query = "UPDATE promotions SET is_active=$1 WHERE id = $2;";
        const values = [is_active, promotionId];
        const result = await pool.query(query, values);

        res.status(200).json({
          message: `Promotions status updated successfully for ID: ${promotionId}`,
          updatedCount: result.rowCount,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
    // DELETE: Delete Payment By Id  API Route
    app.delete("/promotions/:id", async (req, res) => {
      try {
        const promotionId = req.params.id;

        const query = "DELETE FROM promotions WHERE id = $1;";
        const values = [promotionId];
        const result = await pool.query(query, values);

        res.status(200).json({
          message: `Promotions deleted successfully for ID: ${promotionId}`,
          deletedCount: result.rowCount,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    app.post("/apply-promo", async (req, res) => {
      try {
        const { userId, code } = req.body;

        // Check promo validity
        const promoResult = await pool.query(
          "SELECT * FROM promotions WHERE code=$1 AND is_active=true AND CURRENT_DATE BETWEEN start_date AND end_date",
          [code],
        );

        if (promoResult.rows.length === 0)
          return res.status(400).json({ message: "Invalid  promo" });

        const promo = promoResult.rows[0];

        // Check if already used
        const usedCheck = await pool.query(
          "SELECT * FROM user_promotions WHERE user_id=$1 AND promo_id=$2 AND used=$3",
          [userId, promo.id, true],
        );
        if (usedCheck.rows.length > 0)
          return res.status(400).json({ message: "Already Used Promo!" });

        // Record promo as unused initially
        await pool.query(
          "INSERT INTO user_promotions (user_id, promo_id, used) VALUES ($1,$2,false) RETURNING *",
          [userId, promo.id],
        );

        res.json({
          message: "Yay! Your Promo Worked!",
          discount: promo.discount,
        });
      } catch (err) {
        res.status(500).json({ message: "Server error" });
      }
    });

    // Get User Active Promo
    app.get(
      "/user-promotions/:userId/active",
      passport.authenticate("jwt", { session: false }),
      async (req, res) => {
        try {
          const { userId } = req.params;
          if (userId !== req.user.id) {
            return res.status(401).send("unauthorized access");
          }
          const result = await pool.query(
            `SELECT p.code, p.discount, up.id as user_promo_id,up.used as is_used
       FROM user_promotions up
       JOIN promotions p ON up.promo_id = p.id
       WHERE up.user_id=$1 AND up.used=false`,
            [userId],
          );
          res.json({ promo: result.rows[0] || null });
        } catch (err) {
          res.status(500).json({ message: err.message });
        }
      },
    );

    // Mark Promo as Used (Order Complete)
    app.patch("/user-promotions/:userId/:promoId/use", async (req, res) => {
      try {
        const { userId, promoId } = req.params;
        const result = await pool.query(
          "UPDATE user_promotions SET used=true WHERE user_id=$1 AND promo_id=$2 RETURNING *",
          [userId, promoId],
        );
        if (result.rowCount === 0)
          return res
            .status(400)
            .json({ message: "Promo not found or already used" });
        res.json({ message: "Promo marked as used", promo: result.rows[0] });
      } catch (err) {
        res.status(500).json({ message: err.message });
      }
    });

    // ------------ Promotions API Routes End---------//

    // ------------ Message API Routes---------//
    // get super admin
    app.get(
      "/admin/bazarigo",
      passport.authenticate("jwt", { session: false }),
      async (req, res) => {
        try {
          const result = await pool.query(
            `SELECT id AS user_id, full_name AS name, email, profile_img AS img, role
       FROM admins
       WHERE role = 'super admin' AND email='bazarigo.official@gmail.com'
       LIMIT 1`,
          );
          if (!result.rows.length) {
            return res
              .status(404)
              .json({ success: false, message: "Admin not found" });
          }
          res.json({ success: true, admin: result.rows[0] });
        } catch (err) {
          console.error(err);
          res.status(500).json({ success: false, message: "Server error" });
        }
      },
    );

    // Send message

    app.post("/send", upload.single("image"), async (req, res) => {
      let { sender_id, sender_role, receiver_id, receiver_role } = req.body;
      let content = req.body.content; // undefined হলে খালি string
      const id = uuidv4();

      try {
        // admin বাদে সবার জন্য ফিল্টার
        if (
          sender_role !== "admin" ||
          (sender_role !== "super admin" && receiver_role !== "admin") ||
          (receiver_role !== "super admin" && content)
        ) {
          // ফোন ফিল্টার
          const phoneRegex =
            /(\+?\d{1,4}[\s-]?)?(\(?\d{2,4}\)?[\s-]?)?\d{3,4}[\s-]?\d{4}/g;
          content = content.replace(phoneRegex, "💀 Nice Try! Info Deleted 💀");

          // ইমেইল ফিল্টার
          const emailRegex = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
          content = content.replace(emailRegex, "💀 Nice Try! Info Deleted 💀");

          // URL ফিল্টার
          const urlRegex = /(https?:\/\/[^\s]+)/g;
          content = content.replace(urlRegex, "💀 Nice Try! Info Deleted 💀");

          // address keywords
          const addressPattern =
            /\b(house|holding|road|rd|block|sector|village|po|post\s?office|ps|thana|area|lane|flat|floor|building)\s*\d+/gi;

          if (addressPattern.test(content)) {
            content = "💀 Nice Try! Info Deleted 💀";
          }
        }

        // শুধু customer হলে auto reply

        const checkQuery = `
            SELECT * FROM messages
            WHERE (sender_id = $1 AND receiver_id = $2)
               OR (sender_id = $2 AND receiver_id = $1)
          `;
        const checkResult = await pool.query(checkQuery, [
          sender_id,
          receiver_id,
        ]);

        let savedPath = null;
        if (req.file) {
          const safeName = "Message".replace(/\s+/g, "_");
          const uploadDir = path.join(__dirname, "uploads", "messages");
          if (!fs.existsSync(uploadDir))
            fs.mkdirSync(uploadDir, { recursive: true });

          const filename = `${safeName}-${Date.now()}.webp`;
          const filepath = path.join(uploadDir, filename);

          await sharp(req.file.buffer)
            .webp({ lossless: true })
            .toFile(filepath);
          savedPath = `/uploads/messages/${filename}`;
        }

        // মূল message insert
        const result = await pool.query(
          `INSERT INTO messages (id, sender_id, sender_role, receiver_id, receiver_role, content, image_url)
           VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
          [
            id,
            sender_id,
            sender_role,
            receiver_id,
            receiver_role,
            content,
            savedPath,
          ],
        );
        if (result.rowCount > 0) {
          if (sender_role === "customer") {
            if (checkResult.rows.length === 0) {
              const autoId = uuidv4();
              const autoContent =
                "Hello 👋! Thank you for reaching out to us. How can we assist you?";

              await pool.query(
                `INSERT INTO messages (id, sender_id, sender_role, receiver_id, receiver_role, content)
               VALUES ($1,$2,$3,$4,$5,$6)`,
                [
                  autoId,
                  receiver_id,
                  receiver_role,
                  sender_id,
                  sender_role,
                  autoContent,
                ],
              );
            }
          }
          await createNotification({
            userId: receiver_id,
            userRole: receiver_role,
            title: "New Message Received",
            message: `You received a new message.`,
            type: "Message",
            refId: sender_id, // reference to who sent the message
            expiresAt: "7d",
          });
        }

        res.status(200).json({ success: true, message: result.rows[0] });
      } catch (err) {
        console.log(err);
        res.status(500).json({ success: false, error: err.message });
      }
    });

    // Get conversation between two users

    app.get(
      "/conversation/:user1/:user2",
      passport.authenticate("jwt", { session: false }),
      async (req, res) => {
        try {
          const loggedInUserId = req.user.id;
          const otherUserId = req.params.user2;

          // Mark only receiver messages as read
          await pool.query(
            `UPDATE messages
       SET read_status = true
       WHERE sender_id = $1 AND receiver_id = $2`,
            [otherUserId, loggedInUserId],
          );

          const result = await pool.query(
            `SELECT m.*,
        COALESCE(u1.name, s1.full_name, a1.full_name) AS sender_name,
        COALESCE(u1.img, s1.img, a1.profile_img) AS sender_image,
        COALESCE(u2.name, s2.full_name, a2.full_name) AS receiver_name,
        COALESCE(u2.img, s2.img, a2.profile_img) AS receiver_image
       FROM messages m
       LEFT JOIN users u1 ON u1.id = m.sender_id
       LEFT JOIN sellers s1 ON s1.id = m.sender_id
       LEFT JOIN admins a1 ON a1.id = m.sender_id
       LEFT JOIN users u2 ON u2.id = m.receiver_id
       LEFT JOIN sellers s2 ON s2.id = m.receiver_id
       LEFT JOIN admins a2 ON a2.id = m.receiver_id
       WHERE (m.sender_id = $1 AND m.receiver_id = $2)
          OR (m.sender_id = $2 AND m.receiver_id = $1)
       ORDER BY m.created_at ASC`,
            [loggedInUserId, otherUserId],
          );

          res.status(200).json({ success: true, messages: result.rows });
        } catch (err) {
          res.status(500).json({ success: false, error: err.message });
        }
      },
    );

    app.get(
      "/my-messages/:id",
      passport.authenticate("jwt", { session: false }),
      async (req, res) => {
        try {
          const loggedInUserId = req.params.id;
          if (loggedInUserId !== req.user.id) {
            return res.status(401).send("unauthorized access");
          }

          const query = `
WITH all_profiles AS (
  SELECT id, name, email, img, role FROM users
  UNION ALL
  SELECT id, full_name AS name, email, img, role FROM sellers
  UNION ALL
  SELECT id, full_name AS name, email, profile_img AS img, role FROM admins
),
conversations AS (
  SELECT
    CASE WHEN sender_id = $1 THEN receiver_id ELSE sender_id END AS user_id,
    MAX(created_at) AS last_message_time
  FROM messages
  WHERE sender_id = $1 OR receiver_id = $1
  GROUP BY CASE WHEN sender_id = $1 THEN receiver_id ELSE sender_id END
),
last_messages AS (
  SELECT m.*
  FROM messages m
  INNER JOIN conversations c
    ON ((m.sender_id = $1 AND m.receiver_id = c.user_id)
        OR (m.sender_id = c.user_id AND m.receiver_id = $1))
       AND m.created_at = c.last_message_time
)
SELECT
  p.id AS user_id,
  p.name,
  p.email,
  p.img,
  p.role,
  lm.content AS last_message,
  lm.created_at AS last_message_time,
  (
    SELECT COUNT(*)
    FROM messages
    WHERE sender_id = p.id
      AND receiver_id = $1
      AND read_status = FALSE
  ) AS unread_count
  
FROM last_messages lm
JOIN all_profiles p
  ON p.id = CASE WHEN lm.sender_id = $1 THEN lm.receiver_id ELSE lm.sender_id END
ORDER BY lm.created_at DESC;
`;

          const result = await pool.query(query, [loggedInUserId]);

          res.status(200).json({ success: true, messages: result.rows });
        } catch (err) {
          res.status(500).json({ success: false, error: err.message });
        }
      },
    );

    app.get(
      "/messages",
      passport.authenticate("jwt", { session: false }),
      async (req, res) => {
        try {
          const query = `SELECT *
    FROM messages;
    `;
          const result = await pool.query(query);

          res.status(200).json({ success: true, sellers: result.rows });
        } catch (err) {
          res.status(500).json({ success: false, error: err.message });
        }
      },
    );

    // ------------ Message API Routes End---------//
    // ------------ Admin API Routes End---------//

    app.post("/admins", upload.single("profile_img"), async (req, res) => {
      try {
        const payload = req.body;

        // Required fields check
        const email = payload.email;
        if (!email)
          return res.status(400).json({ message: "Email is required" });
        if (!emailRegex.test(email))
          return res.status(400).json({ message: "Invalid email format" });
        if (!passwordRegex.test(payload.password)) {
          return res.status(400).json({
            message: "Password must be min 8 chars with letters & numbers",
          });
        }

        // Check if email exists
        const checkQuery = `
      SELECT 'admin' AS type FROM admins WHERE email = $1
      UNION
      SELECT 'user' AS type FROM users WHERE email = $1
      UNION
      SELECT 'seller' AS type FROM sellers WHERE email = $1
    `;
        const checkResult = await pool.query(checkQuery, [email]);
        if (checkResult.rowCount > 0)
          return res.status(400).json({ message: "Email already exists" });

        const userName = await generateUsername(payload.email, pool, "admins");

        // Multer file
        let savedPath = null;
        if (req.file) {
          const safeName = (payload.full_name || "admin").replace(/\s+/g, "_");
          const uploadDir = path.join(__dirname, "uploads", "admins");
          if (!fs.existsSync(uploadDir))
            fs.mkdirSync(uploadDir, { recursive: true });

          const filename = `${safeName}-${Date.now()}.webp`;
          const filepath = path.join(uploadDir, filename);

          await sharp(req.file.buffer)
            .webp({ lossless: true })
            .toFile(filepath);
          savedPath = `/uploads/admins/${filename}`;
        }

        // Password hash
        const hashedPassword = await bcrypt.hash(payload.password, 12);

        const query = `
      INSERT INTO admins
      (id, full_name, user_name, email, password, phone_number, profile_img, role, permissions, last_login, is_active, created_at, updated_at, address, district, thana, postal_code, date_of_birth, gender)
      VALUES (gen_random_uuid(), $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
      RETURNING *;
    `;

        const values = [
          payload.full_name,
          userName,
          payload.email,
          hashedPassword,
          payload.phone || null,
          savedPath || null,
          payload.role || "admin",
          JSON.stringify(payload.permissions || []),
          null,
          true,
          new Date(),
          null,
          payload.address || null,
          payload.district || null,
          payload.thana || null,
          payload.postal_code || null,
          payload.date_of_birth || null,
          payload.gender || null,
        ];

        const result = await pool.query(query, values);
        res.status(201).json({
          message: "Admin created successfully",
          admin: result.rows[0],
        });
      } catch (error) {
        console.error(error);
        if (error.code === "23505" && error.detail.includes("email")) {
          return res.status(400).json({ message: "Email already exists" });
        }
        res.status(500).json({ message: "Internal server error" });
      }
    });

    app.get(
      "/admins",
      passport.authenticate("jwt", { session: false }),
      verifyAdmin,
      async (req, res) => {
        try {
          const adminQuery = `SELECT id,address, full_name, user_name, email, phone_number, profile_img, role, permissions, last_login, is_active, created_at, updated_at,district,thana,postal_code,date_of_birth,gender,store_name,product_category,business_address FROM admins WHERE role='admin' OR role='super admin';`;
          const moderatorQuery = `SELECT id,address, full_name, user_name, email, phone_number, profile_img, role, permissions, last_login, is_active, created_at, updated_at,district,thana,postal_code,date_of_birth,gender FROM admins WHERE role='moderator';`;

          const adminResult = await pool.query(adminQuery);
          const moderatorResult = await pool.query(moderatorQuery);
          res.status(201).json({
            message: "Admin return successfully",
            admins: adminResult.rows,
            moderators: moderatorResult.rows,
          });
        } catch (error) {
          res.status(500).json({ message: "Server error" });
        }
      },
    );

    app.delete("/admins/:id", async (req, res) => {
      try {
        const { id } = req.params;
        const deleteQuery = `DELETE FROM admins WHERE id=$1 RETURNING *;`;
        const result = await pool.query(deleteQuery, [id]);
        if (result.rowCount === 0) {
          return res.status(404).json({ message: "Admin not found" });
        }
        res.status(200).json({
          message: "Admin deleted successfully",
          admin: result.rows[0],
        });
      } catch (error) {
        res.status(500).json({ message: "Server error" });
      }
    });

    app.patch("/admins/:id", async (req, res) => {
      try {
        const adminId = req.params.id;
        const { is_active } = req.body;
        const query = "UPDATE admins SET is_active=$1 WHERE id = $2;";
        const values = [is_active, adminId];
        const result = await pool.query(query, values);

        res.status(200).json({
          message: `Admins status updated successfully for ID: ${adminId}`,
          updatedCount: result.rowCount,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
    app.patch("/admins/role/:id", async (req, res) => {
      try {
        const adminId = req.params.id;
        const { role } = req.body;
        const query = "UPDATE admins SET role=$1 WHERE id = $2;";
        const values = [role, adminId];
        const result = await pool.query(query, values);

        res.status(200).json({
          message: `Admins role updated successfully for ID: ${adminId}`,
          updatedCount: result.rowCount,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
    app.put(
      "/admins/update/:id",
      upload.fields([
        { name: "profileImg", maxCount: 1 },
        { name: "storeImg", maxCount: 1 },
      ]),
      async (req, res) => {
        try {
          const adminId = req.params.id;
          const payload = req.body; // normal text data
          const files = req.files; // uploaded images

          // Check exists
          const { rows } = await pool.query(
            "SELECT * FROM admins WHERE id=$1",
            [adminId],
          );
          if (rows.length === 0)
            return res.status(404).json({ message: "Admin not found" });

          const oldAdmin = rows[0];

          // Upload dir
          const uploadDir = path.join(__dirname, "uploads", "admins");
          if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
          }

          // SAVE IMAGE HELPERS
          const saveMulterImage = async (file, prefix, name) => {
            if (!file) return null;
            const safeName = name?.replace(/\s+/g, "_") || "admin";
            const filename = `${safeName}_${prefix}_${uuidv4()}.webp`;
            const filepath = path.join(uploadDir, filename);

            await sharp(file.buffer).webp({ quality: 80 }).toFile(filepath);

            return `/uploads/admins/${filename}`;
          };

          // Save new images
          const profile_imgPath = await saveMulterImage(
            files?.profileImg?.[0],
            "profile",
            payload.full_name || oldAdmin.full_name,
          );

          const store_imgPath = await saveMulterImage(
            files?.storeImg?.[0],
            "store",
            payload.store_name || oldAdmin.store_name,
          );

          // Password hash handle
          let hashedPassword = oldAdmin.password;

          if (payload.old_password && payload.new_password) {
            const match = await bcrypt.compare(
              payload.old_password,
              oldAdmin.password,
            );
            if (!match) {
              return res
                .status(400)
                .json({ message: "Old password incorrect" });
            }
            hashedPassword = await bcrypt.hash(payload.new_password, 10);
          }

          const query = `
        UPDATE admins SET
          full_name=$1,
          email=$2,
          password=$3,
          phone_number=$4,
          profile_img=$5,
          permissions=$6,
          address=$7,
          district=$8,
          thana=$9,
          postal_code=$10,
          date_of_birth=$11,
          gender=$12,
          store_name=$13,
          store_img=$14,
          product_category=$15,
          business_address=$16,
          updated_at=NOW()
        WHERE id=$17
        RETURNING *;
      `;

          const values = [
            payload.full_name || oldAdmin.full_name,
            payload.email || oldAdmin.email,
            hashedPassword,
            payload.phone_number || oldAdmin.phone_number,
            profile_imgPath || oldAdmin.profile_img,
            JSON.stringify(payload.permissions || oldAdmin.permissions),
            payload.address || oldAdmin.address,
            payload.district || oldAdmin.district,
            payload.thana || oldAdmin.thana,
            payload.postal_code || oldAdmin.postal_code,
            payload.date_of_birth || oldAdmin.date_of_birth,
            payload.gender || oldAdmin.gender,
            payload.store_name || oldAdmin.store_name,
            store_imgPath || oldAdmin.store_img,
            payload?.product_category || oldAdmin.product_category,
            payload.business_address || oldAdmin.business_address,
            adminId,
          ];

          const result = await pool.query(query, values);
          if (result.rowCount > 0) {
            // Update seller store name in products table
            const updateProductsQuery = `
              UPDATE products
              SET seller_store_name = $1,
              seller_name = $2
              WHERE seller_id = $3;
            `;
            await pool.query(updateProductsQuery, [
              payload.store_name || oldAdmin.store_name,
              payload.full_name || oldAdmin.full_name,
              adminId,
            ]);
          }

          return res.status(200).json({
            message: "Admin updated successfully",
            admin: result.rows[0],
            updatedCount: result.rowCount,
          });
        } catch (error) {
          return res
            .status(500)
            .json({ message: "Internal server error", err: error.message });
        }
      },
    );

    // ------------ Admin API Routes End---------//

    //-------------Admin DashBoard------------------ //

    app.get(
      "/admin-dashboard",
      passport.authenticate("jwt", { session: false }),
      verifyAdmin,
      async (req, res) => {
        try {
          /** Time ranges */
          // Time ranges
          const today = new Date();

          // Last 2 full days (excluding today)
          const startDate = new Date();
          startDate.setDate(today.getDate() - 2);

          // End date is yesterday
          const endDate = new Date();
          endDate.setDate(today.getDate());
          const startStr = startDate.toLocaleString("en-CA", {
            timeZone: "Asia/Dhaka",
            hour12: false,
          });
          const endStr = endDate.toLocaleString("en-CA", {
            timeZone: "Asia/Dhaka",
            hour12: false,
          });

          /** ---------- Recent Orders (Today) ---------- */
          const recentOrdersQuery = `
     SELECT order_id, customer_name, total, order_date
FROM orders
WHERE order_date::date BETWEEN $1 AND $2

ORDER BY order_date DESC
LIMIT 6;

    `;
          const recentOrdersResult = await pool.query(recentOrdersQuery, [
            startStr,
            endStr,
          ]);

          /** ---------- Orders Chart Aggregation ---------- */

          /** ---------- Weekly with missing days = 0 ---------- */
          const weeklyOrdersQuery = `
      WITH last_seven_days AS (
  SELECT generate_series(
    CURRENT_DATE - INTERVAL '6 days',
    CURRENT_DATE,
    INTERVAL '1 day'
  )::date AS day
),
daily_sales AS (
  SELECT 
    order_date::date AS day,
    SUM(total) AS total_sales
  FROM orders
  WHERE order_date >= CURRENT_DATE - INTERVAL '6 days'
  GROUP BY order_date::date
)
SELECT 
  to_char(lsd.day, 'YYYY-MM-DD') AS day,
  COALESCE(ds.total_sales, 0) AS total_sales
FROM last_seven_days lsd
LEFT JOIN daily_sales ds ON ds.day = lsd.day
ORDER BY lsd.day ASC;
    `;
          const weeklyResult = await pool.query(weeklyOrdersQuery);

          /** ---------- Monthly (last 30 days) ---------- */
          const monthlyOrdersQuery = `
      SELECT to_char(order_date::date, 'YYYY-MM-DD') as day,
             SUM(total) as total_sales
      FROM orders
      WHERE order_date >= CURRENT_DATE - INTERVAL '29 days'
      GROUP BY day
      ORDER BY day ASC
    `;
          const monthlyResult = await pool.query(monthlyOrdersQuery);

          /** ---------- Yearly (last 12 months) ---------- */
          const yearlyOrdersQuery = `
      SELECT to_char(date_trunc('month', order_date), 'YYYY-MM') as month,
             SUM(total) as total_sales
      FROM orders
      WHERE order_date >= CURRENT_DATE - INTERVAL '11 months'
      GROUP BY month
      ORDER BY month ASC
    `;
          const yearlyResult = await pool.query(yearlyOrdersQuery);

          /** Map results for frontend charting */
          const mapChart = (rows, labelKey) =>
            rows.map((row) => ({
              label: row[labelKey],
              value: Number(row.total_sales || 0),
            }));

          const ordersChart = {
            weekly: mapChart(weeklyResult.rows, "day"),
            monthly: mapChart(monthlyResult.rows, "day"),
            yearly: mapChart(yearlyResult.rows, "month"),
          };

          /** ---------- Total Sales ---------- */
          const totalSalesQuery = `SELECT SUM(amount) as total_sales FROM payments WHERE status='Approved'`;
          const totalSalesResult = await pool.query(totalSalesQuery);
          const totalSales = Number(totalSalesResult.rows[0].total_sales || 0);

          /** ---------- Category Data ---------- */
          const categoryDataQuery = `
      SELECT category, COUNT(*) as count
      FROM products
      GROUP BY category
    `;
          const categoryDataResult = await pool.query(categoryDataQuery);
          const categoryData = categoryDataResult.rows.map((row) => ({
            label: row.category,
            value: Number(row.count),
          }));

          /** ---------- Send JSON ---------- */
          res.json({
            recentOrders: recentOrdersResult.rows,
            ordersChart,
            totalSales,
            categoryData,
          });
        } catch (err) {
          console.error("Dashboard error:", err);
          res.status(500).json({ message: "Internal server error" });
        }
      },
    );

    app.get(
      "/admin-reports",
      passport.authenticate("jwt", { session: false }),
      verifyAdmin,
      async (req, res) => {
        try {
          const { interval = "monthly", startDate, endDate } = req.query;

          // -------------------- FETCH ORDERS --------------------
          let query = `SELECT * FROM orders WHERE 1=1`;
          const params = [];
          let index = 1;

          if (startDate) {
            query += ` AND order_date::date >= $${index++}`;
            params.push(startDate);
          }
          if (endDate) {
            query += ` AND order_date::date <= $${index++}`;
            params.push(endDate);
          }

          const { rows: orders = [] } = await pool.query(query, params);

          // -------------------- INITIAL METRICS --------------------
          let totalOrders = orders.length;
          let revenue = 0;
          let deliveryRevenue = 0;

          const customerSet = new Set();
          const sellerMap = new Map();
          const categoryMap = new Map();
          const productMap = new Map();
          const productCommissionMap = new Map();
          const ordersByDayMap = new Map();

          // -------------------- INIT DATE MAP --------------------
          if (interval === "weekly") {
            ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].forEach((day) =>
              ordersByDayMap.set(day, 0),
            );
          } else if (interval === "monthly") {
            for (let i = 1; i <= 31; i++) ordersByDayMap.set(i, 0);
          } else if (interval === "yearly") {
            [
              "Jan",
              "Feb",
              "Mar",
              "Apr",
              "May",
              "Jun",
              "Jul",
              "Aug",
              "Sep",
              "Oct",
              "Nov",
              "Dec",
            ].forEach((m) => ordersByDayMap.set(m, 0));
          }

          // -------------------- PROCESS ORDERS --------------------
          for (const order of orders) {
            if (!order) continue;

            customerSet.add(order.customer_email);
            deliveryRevenue += Number(order.delivery_cost || 0);

            const orderDate = new Date(order.order_date);
            if (isNaN(orderDate)) continue;

            // ---- Determine Key
            let key;
            if (interval === "weekly") {
              key = orderDate.toLocaleString("en-US", { weekday: "short" });
            } else if (interval === "monthly") {
              key = orderDate.getDate(); // 1-31
            } else if (interval === "yearly") {
              key = orderDate.toLocaleString("en-US", { month: "short" });
            }

            if (ordersByDayMap.has(key)) {
              ordersByDayMap.set(key, ordersByDayMap.get(key) + 1);
            }

            // ---- Order Items
            const items = order.order_items || [];
            for (const item of items) {
              const sellerId = item?.sellerid;
              const sellerName = item?.seller_name || "-";

              if (!sellerId) continue;

              // Init seller
              if (!sellerMap.has(sellerId)) {
                sellerMap.set(sellerId, {
                  sellerId,
                  sellerName,
                  totalSales: 0,
                  totalCommission: 0,
                  totalEarnings: 0,
                });
              }

              const products = item.productinfo || [];
              for (const prod of products) {
                if (!prod) continue;

                const price =
                  prod.sale_price > 0 ? prod.sale_price : prod.regular_price;

                const qty = prod.qty || 1;
                const amount = price * qty;

                const category = prod.product_category || "Uncategorized";
                const commissionRate = CATEGORY_COMMISSION[category] ?? 0;
                const commissionAmount = amount * commissionRate;
                const sellerEarnings = amount - commissionAmount;

                revenue += amount;
                grossRevenue = revenue + deliveryRevenue;
                productRevenue = revenue;

                // Category
                categoryMap.set(
                  category,
                  (categoryMap.get(category) || 0) + qty,
                );

                // Seller update
                const seller = sellerMap.get(sellerId);
                seller.totalSales += amount;
                seller.totalCommission += commissionAmount;
                seller.totalEarnings += sellerEarnings;

                // Top products
                const productKey = prod.product_Id;
                if (productKey) {
                  if (!productMap.has(productKey)) {
                    productMap.set(productKey, {
                      label: prod.product_name,
                      value: qty,
                    });
                  } else {
                    productMap.get(productKey).value += qty;
                  }
                }

                // Product commission data
                if (productKey) {
                  if (!productCommissionMap.has(productKey)) {
                    productCommissionMap.set(productKey, {
                      productName: prod.product_name,
                      category,
                      price,
                      quantity: qty,
                      commissionRate,
                      commissionAmount,
                      sellerEarnings,
                      sellerId,
                      sellerName,
                    });
                  } else {
                    const ex = productCommissionMap.get(productKey);
                    ex.quantity += qty;
                    ex.commissionAmount += commissionAmount;
                    ex.sellerEarnings += sellerEarnings;
                  }
                }
              }
            }
          }

          // -------------------- BUILD RESPONSE --------------------
          const totalCustomers = customerSet.size;
          const totalSellers = sellerMap.size;
          const averageOrderValue = totalOrders ? revenue / totalOrders : 0;

          const categoryData = Array.from(categoryMap).map(
            ([label, value]) => ({
              label,
              value,
            }),
          );

          const sellerPerformance = Array.from(sellerMap.values()).map((s) => ({
            label: s.sellerName,
            value: s.totalSales,
          }));

          const topSellingProducts = Array.from(productMap.values())
            .sort((a, b) => b.value - a.value)
            .slice(0, 5);

          const ordersByDay = Array.from(ordersByDayMap).map(
            ([label, value]) => ({
              label,
              value,
            }),
          );

          const productCommissionData = Array.from(
            productCommissionMap.values(),
          );
          const sellerCommissionData = Array.from(sellerMap.values());

          return res.json({
            reportType: interval,
            totalOrders,
            orders,
            grossRevenue,
            productRevenue,
            deliveryRevenue,
            totalCustomers,
            totalSellers,
            averageOrderValue,
            categoryData,
            sellerPerformance,
            topSellingProducts,
            ordersByDay,
            productCommissionData,
            sellerCommissionData,
          });
        } catch (err) {
          console.error("Error fetching admin reports:", err);
          return res
            .status(500)
            .json({ message: "Server error fetching reports" });
        }
      },
    );

    app.get(
      "/seller-dashboard/:sellerId",
      passport.authenticate("jwt", { session: false }),
      verifySeller,
      async (req, res) => {
        try {
          const { sellerId } = req.params;
          if (sellerId !== req.user.id) {
            return res.status(401).send("unauthorized access");
          }
          // -----------------------------
          // 1️⃣ Total Products
          // -----------------------------
          const products = await pool.query(
            `SELECT id, product_name, stock,category,subcategory 
       FROM products 
       WHERE seller_id = $1`,
            [sellerId],
          );

          // -----------------------------
          // 2️⃣ Seller Profile
          // -----------------------------
          const sellerProfile = await pool.query(
            `SELECT id, full_name, email, store_name, img, district, thana 
       FROM sellers
       WHERE id = $1`,
            [sellerId],
          );

          // -----------------------------
          // 3️⃣ Total Orders (Seller Wise)
          // -----------------------------
          const orders = await pool.query(
            `SELECT order_id, order_number, order_date, total, customer_name, payment_status
       FROM orders o
       WHERE EXISTS (
          SELECT 1 FROM jsonb_array_elements(o.order_items) item
          WHERE item->>'sellerid' = $1
       )
       ORDER BY order_date DESC`,
            [sellerId],
          );

          // -----------------------------
          // 4️⃣ Revenue Calculation
          // -----------------------------

          // STEP 1: fetch seller items with amount + category
          const query = `
      SELECT
        (prod->>'product_category') AS category,
        (CASE 
          WHEN (prod->>'sale_price')::int > 0 
          THEN (prod->>'sale_price')::int
          ELSE (prod->>'regular_price')::int
        END) * (prod->>'qty')::int AS amount
      FROM orders o,
      LATERAL jsonb_array_elements(o.order_items) AS item,
      LATERAL jsonb_array_elements(item->'productinfo') AS prod
      WHERE item->>'sellerid' = $1
    `;

          const { rows } = await pool.query(query, [sellerId]);

          let grossRevenue = 0;
          let totalCommission = 0;

          rows.forEach((item) => {
            const category = item.category;
            const amount = Number(item.amount);

            const commissionRate = CATEGORY_COMMISSION[category] || 0;
            const commission = amount * commissionRate;

            grossRevenue += amount;
            totalCommission += commission;
          });

          const netRevenue = grossRevenue - totalCommission;

          // -----------------------------
          // 5️⃣ Recent Orders (limit 6)
          // -----------------------------
          const recentOrders = await pool.query(
            `SELECT 
          order_id, order_number, customer_name, total, order_date 
       FROM orders o
       WHERE EXISTS (
          SELECT 1 FROM jsonb_array_elements(o.order_items) item
          WHERE item->>'sellerid' = $1
       )
       ORDER BY order_date DESC
       LIMIT 6`,
            [sellerId],
          );

          // -----------------------------
          // 6️⃣ Inventory / Low stock items
          // -----------------------------
          const lowStock = products.rows.filter((p) => p.stock < 1000);

          // -----------------------------
          // 7️⃣ Sales Trend (Last 7 Days)
          // -----------------------------

          const salesTrendQuery = `
  WITH dates AS (
    SELECT generate_series(
        CURRENT_DATE - INTERVAL '6 days',  -- 7 দিনের জন্য
        CURRENT_DATE,
        INTERVAL '1 day'
    )::date AS date
)
SELECT
    TO_CHAR(d.date, 'YYYY-MM-DD') AS date,
    COALESCE(SUM(
        CASE 
            WHEN (prod->>'sale_price')::int > 0 
            THEN (prod->>'sale_price')::int 
            ELSE (prod->>'regular_price')::int 
        END * (prod->>'qty')::int
    ), 0) AS revenue
FROM dates d
LEFT JOIN orders o
    ON o.order_date::date = d.date
LEFT JOIN jsonb_array_elements(o.order_items) AS item
    ON TRUE
LEFT JOIN jsonb_array_elements(item->'productinfo') AS prod
    ON TRUE
    AND item->>'sellerid' = $1
GROUP BY d.date
ORDER BY d.date ASC;

`;

          const salesTrend = await pool.query(salesTrendQuery, [sellerId]);

          // Format for chart: label + value
          const salesData = salesTrend.rows.map((row) => ({
            label: row.date, // e.g. 2025-11-26
            value: Number(row.revenue),
          }));

          // -----------------------------
          // 8️⃣ Orders by Status
          // -----------------------------
          const orderStatusQuery = `
  SELECT 
      prod->>'order_status' AS status,
      COUNT(*) AS count
  FROM orders o
  CROSS JOIN LATERAL jsonb_array_elements(o.order_items) AS item
  CROSS JOIN LATERAL jsonb_array_elements(item->'productinfo') AS prod
  WHERE item->>'sellerid' = $1
  GROUP BY prod->>'order_status';
`;

          const orderStatus = await pool.query(orderStatusQuery, [sellerId]);

          // -----------------------------
          // 9️⃣ Followers Count
          // -----------------------------
          const followers = await pool.query(
            `SELECT COUNT(*) AS follower_count
       FROM following 
       WHERE seller_id = $1`,
            [sellerId],
          );

          // =============================
          // FINAL RESPONSE
          // =============================
          res.json({
            success: true,

            totalProducts: products.rowCount,
            totalOrders: orders.rowCount,
            revenue: netRevenue,
            recentOrders: recentOrders.rows,
            lowStock,
            salesData,
            ordersByStatus: orderStatus.rows,
            followers: followers.rows[0]?.follower_count || 0,

            sellerProfile: sellerProfile.rows[0] || {},

            products: products.rows,
            orders: orders.rows,
          });
        } catch (error) {
          console.error("Dashboard error:", error);
          res.status(500).json({ success: false, message: "Server Error" });
        }
      },
    );

    // ------------Seller DashBoard End--------------//

    app.get(
      "/seller-reports/:sellerId",
      passport.authenticate("jwt", { session: false }),
      verifySeller,
      async (req, res) => {
        try {
          const { sellerId } = req.params;
          const {
            interval = "monthly",
            startDate,
            endDate,
            status,
          } = req.query;
          if (sellerId !== req.user.id) {
            return res.status(401).send("unauthorized access");
          }
          // Fetch orders for seller with filters
          let orderQuery = `
      SELECT
        o.order_id,
        o.order_date,
        o.order_items,
        o.total
      FROM orders o
      CROSS JOIN LATERAL jsonb_array_elements(o.order_items) AS item
      CROSS JOIN LATERAL jsonb_array_elements(item->'productinfo') AS prod
      WHERE item->>'sellerid' = $1
    `;
          const params = [sellerId];
          let paramIndex = 2;

          if (startDate) {
            orderQuery += ` AND o.order_date >= $${paramIndex}`;
            params.push(startDate);
            paramIndex++;
          }
          if (endDate) {
            orderQuery += ` AND o.order_date <= $${paramIndex}`;
            params.push(endDate);
            paramIndex++;
          }
          if (status && status !== "all") {
            orderQuery += ` AND prod->>'order_status' = $${paramIndex}`;
            params.push(status);
            paramIndex++;
          }

          const { rows: orders } = await pool.query(orderQuery, params);

          // -------------------
          // Maps to calculate metrics
          const revenueMap = new Map();
          const categoryMap = new Map();
          const productMap = new Map();
          const groupedProducts = {};

          orders.forEach((o) => {
            const orderDate = new Date(o.order_date);

            // Determine interval key
            let key, label;
            if (interval === "weekly") {
              const firstDay = new Date(orderDate.getFullYear(), 0, 1);
              const pastDays = (orderDate - firstDay) / 86400000;
              const week = Math.ceil((pastDays + firstDay.getDay() + 1) / 7);
              key = `${orderDate.getFullYear()}-W${week}`;
              label = `Week ${week} ${orderDate.getFullYear()}`;
            } else {
              key = `${orderDate.getFullYear()}-${String(
                orderDate.getMonth() + 1,
              ).padStart(2, "0")}`;
              label = orderDate.toLocaleString("default", {
                month: "short",
                year: "numeric",
              });
            }

            o.order_items.forEach((item) => {
              if (item.sellerid !== sellerId) return;

              item.productinfo.forEach((prod) => {
                const price =
                  prod.sale_price > 0 ? prod.sale_price : prod.regular_price;
                const qty = prod.qty || 1;
                const amount = price * qty;
                const category = prod.product_category || "Uncategorized";
                const commissionRate = CATEGORY_COMMISSION[category] ?? 0;
                const commissionAmount = amount * commissionRate;
                const sellerEarnings = amount - commissionAmount;

                // Revenue per interval
                if (!revenueMap.has(key))
                  revenueMap.set(key, { key, label, revenue: 0 });
                revenueMap.get(key).revenue += sellerEarnings;

                // Category-wise revenue
                if (!categoryMap.has(category)) categoryMap.set(category, 0);
                categoryMap.set(
                  category,
                  categoryMap.get(category) + sellerEarnings,
                );

                // Top products (combine same products)
                const productKey = prod.product_Id;
                if (!productMap.has(productKey)) {
                  productMap.set(productKey, {
                    name: prod.product_name,
                    category,
                    price,
                    stock: prod.variants?.stock || 0,
                    potentialValue: (prod.variants?.stock || 0) * price,
                    quantity: qty,
                    commissionRate,
                    commissionAmount,
                    sellerEarnings,
                  });
                } else {
                  const existing = productMap.get(productKey);
                  existing.potentialValue +=
                    (prod.variants?.stock || 0) * price;
                  existing.quantity += qty;
                  existing.commissionAmount += commissionAmount;
                  existing.sellerEarnings += sellerEarnings;
                }

                // Group products for commission table
                if (!groupedProducts[prod.product_name]) {
                  groupedProducts[prod.product_name] = {
                    sellerName: item.seller_name || "-",
                    productName: prod.product_name,
                    category,
                    price,
                    quantity: qty,
                    commissionRate,
                    commissionAmount,
                    sellerEarnings,
                    amount: price * qty,
                  };
                } else {
                  groupedProducts[prod.product_name].quantity += qty;
                  groupedProducts[prod.product_name].commissionAmount +=
                    commissionAmount;
                  groupedProducts[prod.product_name].sellerEarnings +=
                    sellerEarnings;
                }
              });
            });
          });

          const topProducts = Array.from(productMap.values())
            .sort((a, b) => b.potentialValue - a.potentialValue)
            .slice(0, 5);

          const productCommissionData = Object.values(groupedProducts);

          const sellerSummary = productCommissionData.reduce(
            (acc, p) => {
              acc.totalSales += p.price * p.quantity;
              acc.totalCommission += p.commissionAmount;
              acc.totalEarnings += p.sellerEarnings;
              return acc;
            },
            { totalSales: 0, totalCommission: 0, totalEarnings: 0 },
          );

          return res.json({
            revenueByInterval: Array.from(revenueMap.values()).sort((a, b) =>
              a.key.localeCompare(b.key),
            ),
            categorySales: Array.from(categoryMap.entries()).map(
              ([name, value], i) => ({
                name,
                value,
                color: ["#4F46E5", "#10B981", "#F59E0B", "#EF4444", "#8B5CF6"][
                  i % 5
                ],
              }),
            ),
            topProducts,
            productCommissionData,
            sellerCommissionData: [
              {
                sellerName: req.user.full_name || "-",
                ...sellerSummary,
              },
            ],
          });
        } catch (err) {
          console.error("Error fetching seller reports:", err);
          return res
            .status(500)
            .json({ message: "Server error fetching reports" });
        }
      },
    );

    // GET: User Notifications
    app.get(
      "/notifications",
      passport.authenticate("jwt", { session: false }),
      async (req, res) => {
        try {
          const userId = req.user.id;
          const userRole = req.user.role;

          const query = `
        SELECT * 
        FROM notifications 
        WHERE user_id = $1 AND user_role = $2
        ORDER BY created_at DESC
        LIMIT 50
      `;

          const result = await pool.query(query, [userId, userRole]);

          res.status(200).json({
            message: "Notifications fetched successfully",
            notifications: result.rows,
          });
        } catch (err) {
          res.status(500).json({ message: err.message });
        }
      },
    );

    // PATCH: Mark Notification as read
    app.patch(
      "/notifications/:id/read",
      passport.authenticate("jwt", { session: false }),
      async (req, res) => {
        try {
          const notificationId = req.params.id;
          const userId = req.user.id;
          const userRole = req.user.role;

          const query = `
        UPDATE notifications
        SET is_read = TRUE
        WHERE id = $1 AND user_id = $2 AND user_role = $3
        RETURNING *
      `;

          const result = await pool.query(query, [
            notificationId,
            userId,
            userRole,
          ]);

          if (result.rowCount === 0) {
            return res.status(404).json({ message: "Notification not found" });
          }

          res.status(200).json({
            message: "Notification marked as read",
            notification: result.rows[0],
          });
        } catch (err) {
          res.status(500).json({ message: err.message });
        }
      },
    );
    app.patch(
      "/notifications/read-all",
      passport.authenticate("jwt", { session: false }),
      async (req, res) => {
        try {
          const notificationId = req.params.id;
          const userId = req.user.id;
          const userRole = req.user.role;

          const query = `
        UPDATE notifications
        SET is_read = TRUE
        WHERE  user_id = $1 AND user_role = $2
        RETURNING *
      `;

          const result = await pool.query(query, [userId, userRole]);

          if (result.rowCount === 0) {
            return res.status(404).json({ message: "Notification not found" });
          }

          res.status(200).json({
            message: "Notification marked as read",
            notification: result.rows[0],
          });
        } catch (err) {
          res.status(500).json({ message: err.message });
        }
      },
    );

    // Contact Us Api Route
    app.post("/api/contact", async (req, res) => {
      const { name, email, message } = req.body;

      if (!name || !email || !message) {
        return res.status(400).json({ error: "All fields are required" });
      }

      try {
        const mailOptions = {
          from: `"Bazarigo Contact Form" <${process.env.EMAIL_USER}>`,
          to: process.env.SUPER_ADMIN,
          subject: `New Customer Inquiry Received – ${name}`,
          replyTo: email,
          html: `
<div style="font-family:'Helvetica Neue',Arial,sans-serif; max-width:700px; margin:auto; background:#fafafa; padding:0; border-radius:12px; border:1px solid #e6e6e6;">

  <!-- Header -->
  <div style="background:#FF0055; padding:22px 30px; border-radius:12px 12px 0 0; text-align:center;">
      <h2 style="color:#fff; margin:0; font-size:26px; font-weight:700;">Bazarigo Support Alert</h2>
  </div>

  <!-- Body -->
  <div style="padding:30px;">
    
    <p style="color:#555; text-align:center; margin-top:0; margin-bottom:30px; font-size:15px; line-height:1.6;">
      A new customer inquiry has been submitted through the Bazarigo website. The details are presented below:
    </p>

    <!-- User Info Container -->
    <div style="background:#fff; border:1px solid #ddd; border-radius:10px; padding:20px;">
      
      <div style="margin-bottom:20px;">
        <p style="margin:0; font-size:14px; font-weight:600; color:#333;">Customer Name</p>
        <p style="margin:6px 0 0; color:#555; font-size:15px;">${name}</p>
      </div>

      <div style="margin-bottom:20px;">
        <p style="margin:0; font-size:14px; font-weight:600; color:#333;">Email Address</p>
        <p style="margin:6px 0 0; color:#555; font-size:15px;">${email}</p>
      </div>

      <div>
        <p style="margin:0; font-size:14px; font-weight:600; color:#333;">Message</p>
        <div style="margin-top:8px; background:#f7f7f7; border-radius:8px; padding:15px; color:#444; border:1px solid #ddd; line-height:1.55; font-size:15px;">
          ${message}
        </div>
      </div>

    </div>
  </div>

  <!-- Footer -->
  <div style="text-align:center; padding:18px 10px; border-top:1px solid #eee;">
    
    <p style="margin:5px 0 0; font-size:13px; color:#888;">© ${new Date().getFullYear()} Bazarigo. All rights reserved.</p>
  </div>

</div>
`,
        };

        await transporter.sendMail(mailOptions);

        res.status(200).json({ message: "Message sent successfully!" });
      } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Something went wrong" });
      }
    });
  } finally {
    // Ensures that the client will close when you finish/error
    // await pool.end();
  }
}
run().catch(console.dir);
app.get("/", (req, res) => {
  res.send(`Welcome to Bazarigo Server! `);
});

app.listen(port, async () => {
  console.log(`Time: ${Date.now()}`);
  console.log(`Example app listening at http://localhost:${port} `);
});
