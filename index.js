const express = require("express");
const uuidv4 = require("uuid").v4;
const cors = require("cors");
const pool = require("./db");
const jwt = require("jsonwebtoken");
const path = require("path");
const fs = require("fs");
const sharp = require("sharp");
const sanitizeHtml = require("sanitize-html");
const cron = require("node-cron");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const passport = require("passport");
const cookieParser = require("cookie-parser");
const { default: axios } = require("axios");
const transporter = require("./mailer");
const ExcelJS = require("exceljs");
const multer = require("multer");

const createNotification = require("./createNotification");

const storage = multer.memoryStorage();
const upload = multer({ storage });

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
      [username]
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
          [email, profile.id]
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
            const uploadDir = path.join(__dirname, "uploads");
            if (!fs.existsSync(uploadDir))
              fs.mkdirSync(uploadDir, { recursive: true });

            await sharp(buffer)
              .resize(256, 256) // ইচ্ছেমতো সাইজ
              .webp({ lossless: true })
              .toFile(path.join(uploadDir, filename));

            savedPath = `/uploads/${filename}`;
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
            ]
          );

          user = insertResult.rows[0];
        }

        cb(null, user);
      } catch (err) {
        cb(err, null);
      }
    }
  )
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
  })
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

const app = express();
const port = 3000;

app.use(
  cors({
    origin: [`https://bazarigo.com`],
    credentials: true,
  })
);

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use(passport.initialize());

app.use(cookieParser());

require("dotenv").config();

function generateId(name) {
  const uniqueId = uuidv4().replace(/-/g, "").slice(0, 12); // UUID থেকে ছোট আইডি
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

async function run() {
  try {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const passwordRegex =
      /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_\-+=<>?])[A-Za-z\d!@#$%^&*()_\-+=<>?]{8,}$/;
    const CATEGORY_COMMISSION = {
      Fashion: 0.1,
      Electronics: 0.05,
      "Health & Beauty": 0.12,
      Sports: 0.08,
      Groceries: 0.03,
      "Home & Living": 0.04,
    };
    // Database connection and operations would go here

    app.get("/api/download-excel", async (req, res) => {
      try {
        const workbook = new ExcelJS.Workbook();
        const sheet = workbook.addWorksheet("Products");

        // Column definitions
        sheet.columns = [
          { header: "productName", key: "productName", width: 30 },
          { header: "brand", key: "brand", width: 30 },
          { header: "regular_price", key: "regular_price", width: 30 },
          { header: "sale_price", key: "sale_price", width: 15 },
          { header: "discount", key: "discount", width: 30 },
          { header: "stock", key: "stock", width: 30 },
          { header: "category", key: "category", width: 30 },
          { header: "subcategory", key: "subcategory", width: 30 },
          { header: "description", key: "description", width: 30 },
          { header: "images", key: "images", width: 30 },
          { header: "extras", key: "extras", width: 50 },
        ];

        // Header bold করার জন্য
        sheet.getRow(1).eachCell((cell) => {
          cell.font = { bold: true };
          cell.alignment = { horizontal: "center", vertical: "middle" };
        });

        // Sample data – replace with database data in production
        sheet.addRow({
          productName: "(enter product name)",
          brand: "(enter brand)",
          regular_price: "(enter regular price)",
          sale_price: "(enter sale price)",
          discount: "(enter discount)",
          stock: "(enter stock amount)",
          category: "(enter category)",
          subcategory: "(enter sub category)",
          description: "(enter product description)",
          images: "(upload product image manually)",
          extras: JSON.stringify({
            variants: [
              {
                size: "Enter size here (e.g., XL)",
                color: "Enter color here (e.g., White)",
                material: "Enter material here (e.g., Cotton)",
                stock: "Enter stock quantity here (e.g., 10)",
                regular_price: "Enter regular price here (e.g., 400)",
                sale_price: "Enter sale price here (0 if no discount)",
              },
            ],
            notes: [
              "প্রতিটি ভেরিয়েন্ট আলাদা করে লিখুন।",
              "sale_price যদি না থাকে, 0 লিখুন।",
              "Stock এবং price সঠিকভাবে আপডেট করুন।",
            ],
          }),
        });
        sheet.addRow({});

        const exampleRow = sheet.addRow([
          "Example: Enter product information here",
        ]);

        // 2) Merge all columns (A থেকে তোমার শেষ column পর্যন্ত)
        sheet.mergeCells(`A${exampleRow.number}:K${exampleRow.number}`);
        const mergedCell = sheet.getCell(`A${exampleRow.number}`);
        mergedCell.alignment = {
          horizontal: "center",
          vertical: "middle",
          wrapText: true,
        };
        mergedCell.font = { bold: true };
        sheet.getRow(exampleRow.number).height = 50;

        sheet.addRow({
          productName: "Stylish Ladies Overcoat",
          brand: "Brand X",
          regular_price: 1000,
          sale_price: 850,
          discount: 15,
          stock: 50,
          category: "Fashion",
          subcategory: "Women’s Clothing",
          description: "This is an example description of the product.",
          images: "image1.jpg, image2.jpg",
          extras: JSON.stringify({
            variants: [
              {
                size: "XL",
                color: "Light Brown",
                stock: 10,
                material: "PU Leather",
                sale_price: 0,
                regular_price: 1200,
              },
              {
                size: "XL",
                color: "Russet",
                stock: 10,
                material: "PU Leather",
                sale_price: 0,
                regular_price: 1200,
              },
              {
                size: "XL",
                color: "Black",
                stock: 10,
                material: "PU Leather",
                sale_price: 0,
                regular_price: 1200,
              },
              {
                size: "XL",
                color: "Maroon",
                stock: 10,
                material: "PU Leather",
                sale_price: 0,
                regular_price: 1200,
              },
              {
                size: "XL",
                color: "Dark Green",
                stock: 10,
                material: "PU Leather",
                sale_price: 0,
                regular_price: 1200,
              },
              {
                size: "XL",
                color: "Navy Blue",
                stock: 10,
                material: "PU Leather",
                sale_price: 0,
                regular_price: 1200,
              },
              {
                size: "XL",
                color: "Ice Gray",
                stock: 10,
                material: "PU Leather",
                sale_price: 0,
                regular_price: 1200,
              },
              {
                size: "L",
                color: "Light Brown",
                stock: 10,
                material: "PU Leather",
                sale_price: 0,
                regular_price: 1200,
              },
              {
                size: "L",
                color: "Russet",
                stock: 10,
                material: "PU Leather",
                sale_price: 0,
                regular_price: 1200,
              },
              {
                size: "L",
                color: "Black",
                stock: 10,
                material: "PU Leather",
                sale_price: 0,
                regular_price: 1200,
              },
              {
                size: "L",
                color: "Maroon",
                stock: 10,
                material: "PU Leather",
                sale_price: 0,
                regular_price: 1200,
              },
              {
                size: "L",
                color: "Dark Green",
                stock: 10,
                material: "PU Leather",
                sale_price: 0,
                regular_price: 1200,
              },
              {
                size: "L",
                color: "Navy Blue",
                stock: 10,
                material: "PU Leather",
                sale_price: 0,
                regular_price: 1200,
              },
              {
                size: "L",
                color: "Ice Gray",
                stock: 10,
                material: "PU Leather",
                sale_price: 0,
                regular_price: 1200,
              },
              {
                size: "M",
                color: "Light Brown",
                stock: 10,
                material: "PU Leather",
                sale_price: 0,
                regular_price: 1200,
              },
              {
                size: "M",
                color: "Russet",
                stock: 10,
                material: "PU Leather",
                sale_price: 0,
                regular_price: 1200,
              },
              {
                size: "M",
                color: "Black",
                stock: 10,
                material: "PU Leather",
                sale_price: 0,
                regular_price: 1200,
              },
              {
                size: "M",
                color: "Maroon",
                stock: 10,
                material: "PU Leather",
                sale_price: 0,
                regular_price: 1200,
              },
              {
                size: "M",
                color: "Dark Green",
                stock: 10,
                material: "PU Leather",
                sale_price: 0,
                regular_price: 1200,
              },
              {
                size: "M",
                color: "Navy Blue",
                stock: 10,
                material: "PU Leather",
                sale_price: 0,
                regular_price: 1200,
              },
              {
                size: "M",
                color: "Ice Gray",
                stock: 10,
                material: "PU Leather",
                sale_price: 0,
                regular_price: 1200,
              },
            ],
          }),
        });

        // Set response headers
        res.setHeader(
          "Content-Type",
          "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        );
        res.setHeader(
          "Content-Disposition",
          "attachment; filename=Products.xlsx"
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
       sale_price AS price, 
       images, 
       'product' AS type
FROM products
WHERE product_name ILIKE $1
ORDER BY product_name, createdAt DESC, id ASC;`,
        [search]
      );

      // 2) Match shops (sellers)
      const shopSearch = await pool.query(
        `SELECT DISTINCT ON (store_name) id, store_name AS title, store_img, 'shop' AS type
FROM sellers
WHERE store_name ILIKE $1 OR full_name ILIKE $1
ORDER BY store_name, id ASC;
`,
        [search]
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
      }
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
          const query = "SELECT * FROM products;";
          const result = await pool.query(query);
          res.status(200).json({
            message: "Products route is working!",
            products: result.rows,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      }
    );

    //GET: Get Single Product API Route
    app.get(
      "/products/:id",

      async (req, res) => {
        try {
          const productId = req.params.id;
          const query = "SELECT * FROM products WHERE id =$1;";
          const values = [productId];
          const result = await pool.query(query, values);

          res.status(200).json({
            message: `Single product route is working for ID: ${productId}`,
            product: result.rows[0],
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      }
    );
    //GET: Get Products By SellerId API Route
    app.get(
      "/products/seller/:sellerId",

      async (req, res) => {
        try {
          const { sellerId } = req.params;

          const query = "SELECT * FROM products WHERE seller_id =$1;";
          const values = [sellerId];
          const result = await pool.query(query, values);

          res.status(200).json({
            message: `Seller product route is working for ID: ${sellerId}`,
            products: result.rows,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      }
    );

    //POST: Create Product API route

    app.post(
      "/products",
      passport.authenticate("jwt", { session: false }),
      upload.array("images"), // images + videos mixed
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
            description,
            stock,
            brand,
            weight,
            extras,
          } = req.body;

          const user = req.user;
          let sellerId, sellerName, sellerStoreName, sellerRole;

          if (user.role === "seller" || user.role === "super admin") {
            sellerId = user.id;
            sellerName = user.full_name;
            sellerStoreName = user.store_name;
            sellerRole = user.role;
          } else {
            const bazarigo = await pool.query(
              "SELECT id, full_name, store_name, role FROM admins WHERE email='bazarigo.official@gmail.com' LIMIT 1;"
            );
            if (bazarigo.rows.length > 0) {
              sellerId = bazarigo.rows[0].id;
              sellerName = bazarigo.rows[0].full_name;
              sellerStoreName = bazarigo.rows[0].store_name;
              sellerRole = bazarigo.rows[0].role;
            }
          }

          const sanitizedDescription = sanitizeHtml(description, {
            allowedTags: sanitizeHtml.defaults.allowedTags.concat(["img"]),
            allowedAttributes: {
              ...sanitizeHtml.defaults.allowedAttributes,
              img: ["src", "alt", "width", "height"],
            },
          });

          const productId = uuidv4();
          const uploadDirs = {
            image: path.join(__dirname, "uploads", "products", "images"),
            video: path.join(__dirname, "uploads", "products", "videos"),
          };

          // Create directories if not exist
          for (const dir of Object.values(uploadDirs)) {
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
          }

          const savedPaths = await Promise.all(
            req.files.map(async (file, i) => {
              const mime = file.mimetype;

              if (mime.startsWith("image")) {
                const filename = `${productName}-${i}.webp`;
                const filepath = path.join(uploadDirs.image, filename);
                await sharp(file.buffer)
                  .webp({ lossless: true })
                  .toFile(filepath);
                return `/uploads/products/images/${filename}`;
              } else if (mime.startsWith("video")) {
                const ext = mime.split("/")[1];
                const filename = `${productName}-${i}.${ext}`;
                const filepath = path.join(uploadDirs.video, filename);
                await fs.promises.writeFile(filepath, file.buffer);
                return `/uploads/products/videos/${filename}`;
              }
              return null;
            })
          );

          const query = `
        INSERT INTO products (
          id, product_name, regular_price, sale_price, discount, rating,
          isBestSeller, isHot, isNew, isTrending, isLimitedStock, isExclusive, isFlashSale,
          category, subcategory, description, stock, brand, weight, images, extras,
          createdAt, updatedAt, seller_id, seller_name, seller_store_name, reviews, seller_role
        ) VALUES (
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
          $14,$15,$16,$17,$18,$19,$20,$21,NOW(),
          $22,$23,$24,$25,$26,$27
        ) RETURNING *;
      `;

          const values = [
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
            sanitizedDescription || null,
            stock || 0,
            brand || null,
            weight || 1,
            savedPaths,
            extras ? extras : {},
            null,
            sellerId || null,
            sellerName || null,
            sellerStoreName || "",
            [],
            sellerRole || "",
          ];

          const result = await pool.query(query, values);

          res.status(201).json({
            message: "Product created successfully",
            createdCount: result.rowCount,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      }
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

          for (const item of products) {
            item.id = uuidv4();

            let sellerId, sellerName, sellerStoreName, sellerRole;
            const user = req.user;

            if (user.role === "seller") {
              // Logged-in seller এর নিজের তথ্য ব্যবহার
              sellerId = user.id;
              sellerName = user.full_name;
              sellerStoreName = user.store_name;
              sellerRole = user.role;
            } else {
              // Admin এর ক্ষেত্রে `bazarigo` স্টোর ব্যবহার
              const bazarigo = await pool.query(
                "SELECT id, full_name, store_name,role FROM admins WHERE email='bazarigo.official@gmail.com' LIMIT 1;"
              );
              if (bazarigo.rows.length > 0) {
                sellerId = bazarigo.rows[0].id;
                sellerName = bazarigo.rows[0].full_name;
                sellerStoreName = bazarigo.rows[0].store_name;
                sellerRole = bazarigo.rows[0].role;
              }
            }
            // --- sanitize description ---
            const sanitizedDescription = sanitizeHtml(item.description || "", {
              allowedTags: sanitizeHtml.defaults.allowedTags.concat(["img"]),
              allowedAttributes: {
                ...sanitizeHtml.defaults.allowedAttributes,
                img: ["src", "alt", "width", "height"],
              },
            });

            const uploadDirs = {
              image: path.join(__dirname, "uploads", "products", "images"),
              video: path.join(__dirname, "uploads", "products", "videos"),
            };

            // Create directories if not exist
            for (const dir of Object.values(uploadDirs)) {
              if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            }

            // --- process images ---
            const savedPaths = (
              await Promise.all(
                (item.images || []).map(async (imgStr) => {
                  if (!imgStr) return null;

                  if (imgStr.startsWith("data:image/")) {
                    const base64Data = imgStr.replace(
                      /^data:image\/\w+;base64,/,
                      ""
                    );
                    const buffer = Buffer.from(base64Data, "base64");

                    const safeName = (item.productName || "product").replace(
                      /\s+/g,
                      "_"
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
                })
              )
            ).filter(Boolean);

            // --- database insert ---
            const query = `
        INSERT INTO products (
          id, product_name, regular_price, sale_price, discount, rating,
          isBestSeller, isHot, isNew, isTrending, isLimitedStock, isExclusive, isFlashSale,
          category, subcategory, description, stock, brand, weight, images, extras,
          createdAt, updatedAt, seller_id, seller_name, seller_store_name,reviews,seller_role
        ) VALUES (
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
          $14,$15,$16,$17,$18,$19,$20,$21,NOW(),
          $22,$23,$24,$25,$26,$27
        ) RETURNING *;
      `;

            const values = [
              item.id,
              item.productName || "Untitled",
              item.regular_price || 0,
              item.sale_price || 0,
              item.discount || 0,
              parseFloat(item.rating) || 0,
              item.isBestSeller || false,
              item.isHot || false,
              item.isNew || true,
              item.isTrending || false,
              item.isLimitedStock || false,
              item.isExclusive || false,
              item.isFlashSale || false,
              item.category || null,
              item.subcategory || null,
              sanitizedDescription,
              item.stock || 0,
              item.brand || null,
              parseFloat(item.weight) || 1,
              savedPaths, // pg converts JS array to TEXT[]
              item.extras || {}, // pg converts JS object to JSONB

              null,
              sellerId || null,
              sellerName || null,
              sellerStoreName || "",
              [],
              sellerRole,
            ];

            const result = await pool.query(query, values);
            insertedProducts.push(result.rows[0]);
          }

          res.status(201).json({
            message: "Bulk products uploaded successfully",
            insertedCount: insertedProducts.length,
            insertedProducts,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      }
    );

    // PUT : Update Product By ID
    app.put(
      "/products/:id",
      passport.authenticate("jwt", { session: false }),
      upload.array("images"), // multer middleware
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
            description,
            stock,
            brand,
            extras,
          } = req.body;

          const uploadDirs = {
            image: path.join(__dirname, "uploads", "products", "images"),
            video: path.join(__dirname, "uploads", "products", "videos"),
          };

          // create directories if not exist
          for (const dir of Object.values(uploadDirs)) {
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
          }
          // previous paths নেওয়া
          const existingPaths = req.body.existingPaths
            ? JSON.parse(req.body.existingPaths)
            : [];

          // নতুন upload হওয়া ফাইলগুলো process
          const newPaths = await Promise.all(
            (req.files || []).map(async (file, index) => {
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
            })
          );

          // merge old + new
          const savedPaths = [...existingPaths, ...newPaths].filter(Boolean);

          const sanitizedDescription = sanitizeHtml(description, {
            allowedTags: sanitizeHtml.defaults.allowedTags.concat(["img"]),
            allowedAttributes: {
              ...sanitizeHtml.defaults.allowedAttributes,
              img: ["src", "alt", "width", "height"],
            },
          });

          const query = `
            UPDATE products SET
              product_name=$1, regular_price=$2, sale_price=$3, discount=$4, rating=$5,
              isBestSeller=$6, isHot=$7, isNew=$8, isTrending=$9, isLimitedStock=$10, isExclusive=$11, isFlashSale=$12,
              category=$13, subcategory=$14, description=$15, stock=$16, brand=$17, images=$18, extras=$19,
              updatedAt=NOW()
            WHERE id=$20;
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
            extras ? extras : {},

            productId,
          ];

          const result = await pool.query(query, values);

          res.status(200).json({
            message: `Product updated successfully for ID: ${productId}`,
            updatedCount: result.rowCount,
            paths: savedPaths,
          });
        } catch (err) {
          console.error(err);
          res.status(500).json({ message: err.message });
        }
      }
    );

    // PUT: Add a single review to a product

    app.put(
      "/products/:id/reviews",
      upload.array("images"), // "images" হলো frontend FormData field name
      async (req, res) => {
        try {
          const productId = req.params.id;
          const { name, comment, rating, date } = req.body;

          if (!name || !comment) {
            return res.status(400).json({ message: "Missing required fields" });
          }

          // Multer files থেকে WebP save & path collect
          const savedPaths = await Promise.all(
            (req.files || []).map(async (file, i) => {
              try {
                const filename = `review-${Date.now()}-${i}.webp`;
                const filepath = path.join(__dirname, "uploads", filename);

                await sharp(file.buffer)
                  .webp({ lossless: true })
                  .toFile(filepath);

                return `/uploads/${filename}`;
              } catch (err) {
                console.error(`Failed to save image ${i}:`, err.message);
                return null;
              }
            })
          );

          const finalSavedPaths = savedPaths.filter((p) => p !== null);

          const newReview = {
            name,
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
      }
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
            [id]
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
      }
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
                : q
            );
          } else {
            updatedQuestions = questions.map((q) =>
              q.id === q_id
                ? { ...q, answer, answeredByAdmin: true, replyDate }
                : q
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
      }
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
              [ids]
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
      }
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
              [productId]
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
      }
    );

    //GET: Just Arrived API Route
    app.get("/just-arrived", async (req, res) => {
      try {
        const query = `
      SELECT id, product_name,regular_price, sale_price, discount, rating,category, isBestSeller, isNew, images,reviews
      FROM products
      WHERE createdat >= NOW() - INTERVAL '15 days'
      ORDER BY createdat DESC
      LIMIT 20;
    `;

        const result = await pool.query(query);

        res.status(200).json({
          message: "Just Arrived route is working!",
          products: result.rows,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
    cron.schedule("0 0 * * *", async () => {
      try {
        const updateQuery = `
      UPDATE products
      SET isNew = false
      WHERE createdat < NOW() - INTERVAL '15 days';
    `;

        await pool.query(updateQuery);
      } catch (error) {
        console.error("Cron error:", error.message);
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
            p.isBestSeller,
            p.isNew,
            p.reviews,
            SUM((prod->>'qty')::int) AS sold_quantity,
            true AS istrending
        FROM products p
        JOIN orders o
            ON o.order_date >= NOW() - INTERVAL '7 days'
        CROSS JOIN LATERAL jsonb_array_elements(o.order_items) AS item
        CROSS JOIN LATERAL jsonb_array_elements(item->'productinfo') AS prod
        WHERE (prod->>'product_Id') = p.id
        GROUP BY p.id
        HAVING SUM((prod->>'qty')::int) >= 1
           AND (
               p.rating >= 4
               OR COALESCE((
                   SELECT AVG((r->>'rating')::numeric)
                   FROM unnest(p.reviews) AS r
               ), 0) >= 4
           )
        ORDER BY sold_quantity DESC
        LIMIT 20;

                `;

        const result = await pool.query(query);
        return res.status(200).json({
          message: "Trending Products route is working!",

          products: result.rows,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    cron.schedule("0 0 * * *", async () => {
      try {
        // Update trending products
        const query = `
      -- Set trending = true for products sold in last 7 days AND rating criteria
      UPDATE products p
      SET istrending = true
      FROM (
          SELECT (prod->>'product_Id') AS product_id, SUM((prod->>'qty')::int) AS sold_qty
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

      -- Set trending = false for products not meeting criteria
      UPDATE products
      SET istrending = false
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

        await pool.query(query);
      } catch (error) {
        console.error("Error updating trending products:", error);
      }
    });

    // Flash Sale Products API Routes

    //GET: Get Active Flash Sale Products

    app.get("/flash-sale/active", async (req, res) => {
      const client = await pool.connect();
      try {
        const nowInSeconds = Math.floor(Date.now() / 1000);
        const query = `SELECT * FROM flashSaleProducts ORDER BY start_time ASC;`;
        const result = await client.query(query);

        let activeSale = null;

        await client.query("BEGIN"); // transaction শুরু

        for (const sale of result.rows) {
          const start = Number(sale.start_time);
          const end = Number(sale.end_time);
          const shouldBeActive = nowInSeconds >= start && nowInSeconds < end;

          // ১️⃣ flashSaleProducts.isactive আপডেট
          await client.query(
            `UPDATE flashSaleProducts SET isactive = $1 WHERE id = $2`,
            [shouldBeActive, sale.id]
          );

          const saleProducts = sale.sale_products || [];
          const productIds = saleProducts.map((p) => p.id);

          if (productIds.length > 0) {
            // ২️⃣ মূল products টেবিলের isflashsale আপডেট
            await client.query(
              `UPDATE products SET isflashsale = $1 WHERE id = ANY($2)`,
              [shouldBeActive, productIds]
            );

            // ৩️⃣ flashSaleProducts JSON ফিল্ডের প্রতিটি প্রোডাক্টে isflashsale মান আপডেট
            const updatedSaleProducts = saleProducts.map((p) => ({
              ...p,
              isflashsale: shouldBeActive,
            }));

            await client.query(
              `UPDATE flashSaleProducts SET sale_products = $1 WHERE id = $2`,
              [JSON.stringify(updatedSaleProducts), sale.id]
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

    // ✅ Cron job: check every minute and delete expired flash sales

    cron.schedule("* * * * *", async () => {
      try {
        const now = Math.floor(Date.now() / 1000);

        // শেষ হওয়া ফ্ল্যাশ সেলগুলো সিলেক্ট
        const selectQuery = `SELECT id, sale_products FROM flashSaleProducts WHERE end_time <= $1`;
        const expiredResult = await pool.query(selectQuery, [now]);
        if (expiredResult.rowCount === 0) return;

        const flashSales = expiredResult.rows;

        for (const sale of flashSales) {
          let flashProducts;
          try {
            flashProducts = sale.sale_products;
          } catch (err) {
            console.error(
              `[FlashSale] Invalid JSON for sale id ${sale.id}`,
              err.message
            );
            continue;
          }

          for (const flashProd of flashProducts) {
            const productRes = await pool.query(
              `SELECT * FROM products WHERE id = $1`,
              [flashProd.id]
            );
            if (productRes.rowCount === 0) continue;

            const mainProduct = productRes.rows[0];

            const mainVariants = mainProduct.extras?.variants || [];
            const flashVariants = flashProd.extras?.variants || [];

            if (flashVariants.length > 0 && mainVariants.length > 0) {
              // ক্রম অনুযায়ী ভেরিয়েন্ট স্টক যোগ
              const updatedVariants = mainVariants.map((v, i) => {
                const fVar = flashVariants[i];
                return fVar
                  ? { ...v, stock: (v.stock || 0) + (fVar.stock || 0) }
                  : v;
              });

              mainProduct.extras = {
                ...mainProduct.extras,
                variants: updatedVariants,
              };
              mainProduct.stock = updatedVariants.reduce(
                (sum, v) => sum + (v.stock || 0),
                0
              );
            } else {
              mainProduct.stock =
                (mainProduct.stock || 0) + (flashProd.stock || 0);
            }

            mainProduct.isflashsale = false;

            // প্রোডাক্ট আপডেট
            await pool.query(
              `UPDATE products SET stock=$1, extras=$2, isFlashSale=$3 WHERE id=$4`,
              [
                mainProduct.stock,
                JSON.stringify(mainProduct.extras || {}),
                mainProduct.isflashsale,
                mainProduct.id,
              ]
            );
            // 🔹 Update carts: reset flash price & regular price
            // 🔹 Update carts: reset flash price & regular price
            const cartsRes = await pool.query(
              `SELECT cartid, productinfo
   FROM carts
   WHERE EXISTS (
     SELECT 1
     FROM jsonb_array_elements(productinfo) AS prod
     WHERE prod->>'product_Id' = $1
   )`,
              [mainProduct.id] // mainProduct.id string হিসেবে pass করতে হবে
            );

            const updatePromises = cartsRes.rows.map(async (cart) => {
              const updatedProductInfo = cart.productinfo.map((prod) => {
                if (prod.product_Id === mainProduct.id && prod.isflashsale) {
                  // mainProduct.extras.variants ধরে update

                  return {
                    ...prod,
                    isflashsale: false,

                    sale_price: mainProduct.sale_price, // main product এর sale_price
                    regular_price: mainProduct.regular_price, // main product এর regular_price
                  };
                }
                return prod;
              });

              const result = await pool.query(
                `UPDATE carts SET productinfo = $1 WHERE cartid = $2`,
                [JSON.stringify(updatedProductInfo), cart.cartid]
              );

              return result;
            });

            await Promise.all(updatePromises);
          }
        }

        // ফ্ল্যাশ সেল ডিলিট
        const idsToDelete = flashSales.map((f) => f.id);
        await pool.query(
          `DELETE FROM flashSaleProducts WHERE id = ANY($1::int[])`,
          [idsToDelete]
        );
      } catch (err) {
        console.error("[FlashSale] Cron auto-delete error:", err);
      }
    });

    //DELETE: Delete Flash Sale by ID

    app.delete("/flash-sale/:id", async (req, res) => {
      try {
        const { id } = req.params;

        // ১️⃣ আগে ফ্ল্যাশ সেল ডাটা আনা
        const getQuery =
          "SELECT sale_products FROM flashSaleProducts WHERE id = $1";
        const result = await pool.query(getQuery, [id]);

        if (result.rowCount === 0) {
          return res.status(404).json({ message: "Flash sale not found" });
        }

        const saleProducts = result.rows[0].sale_products;

        // ২️⃣ প্রতিটি প্রোডাক্ট স্টক restore করা
        for (const flashProd of saleProducts) {
          const productRes = await pool.query(
            `SELECT * FROM products WHERE id = $1`,
            [flashProd.id]
          );

          if (productRes.rowCount === 0) continue;

          const mainProduct = productRes.rows[0];

          const mainVariants = mainProduct.extras?.variants || [];
          const flashVariants = flashProd.extras?.variants || [];

          // 👉 যদি variant থাকে
          if (flashVariants.length > 0 && mainVariants.length > 0) {
            const updatedVariants = mainVariants.map((v, i) => {
              const fv = flashVariants[i];
              return fv ? { ...v, stock: (v.stock || 0) + (fv.stock || 0) } : v;
            });

            mainProduct.extras = {
              ...mainProduct.extras,
              variants: updatedVariants,
            };

            mainProduct.stock = updatedVariants.reduce(
              (sum, v) => sum + (v.stock || 0),
              0
            );
          }
          // 👉 No variant → single product
          else {
            mainProduct.stock =
              (mainProduct.stock || 0) + (flashProd.stock || 0);
          }

          mainProduct.isflashsale = false;

          // ৩️⃣ প্রোডাক্ট আপডেট
          await pool.query(
            `UPDATE products 
         SET stock=$1, extras=$2, isflashsale=$3 
         WHERE id=$4`,
            [
              mainProduct.stock,
              JSON.stringify(mainProduct.extras || {}),
              mainProduct.isflashsale,
              mainProduct.id,
            ]
          );
          // 🔹 Update carts: reset flash price & regular price
          const cartsRes = await pool.query(
            `SELECT cartid, productinfo
   FROM carts
   WHERE EXISTS (
     SELECT 1
     FROM jsonb_array_elements(productinfo) AS prod
     WHERE prod->>'product_Id' = $1
   )`,
            [mainProduct.id] // mainProduct.id string হিসেবে pass করতে হবে
          );

          const updatePromises = cartsRes.rows.map(async (cart) => {
            const updatedProductInfo = cart.productinfo.map((prod) => {
              if (prod.product_Id === mainProduct.id && prod.isflashsale) {
                // mainProduct.extras.variants ধরে update

                return {
                  ...prod,
                  isflashsale: false,

                  sale_price: mainProduct.sale_price, // main product এর sale_price
                  regular_price: mainProduct.regular_price, // main product এর regular_price
                };
              }
              return prod;
            });

            const result = await pool.query(
              `UPDATE carts SET productinfo = $1 WHERE cartid = $2`,
              [JSON.stringify(updatedProductInfo), cart.cartid]
            );

            return result;
          });

          await Promise.all(updatePromises);
        }

        // ৪️⃣ flashSaleProducts রেকর্ড ডিলিট করা
        await pool.query("DELETE FROM flashSaleProducts WHERE id = $1", [id]);

        res.status(200).json({
          message: "Flash sale deleted & stocks restored successfully",
        });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: error.message });
      }
    });

    //POST: Create a new flash sale setting
    app.post("/flash-sale/toggle-auto", async (req, res) => {
      const { enable } = req.body;
      try {
        const existing = await pool.query(
          "SELECT * FROM flash_sale_settings LIMIT 1;"
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
          [enable]
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
          [enable]
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
      }
    );
    // Auto Generate process
    cron.schedule("0 * * * *", async () => {
      try {
        const settingsRes = await pool.query(
          "SELECT is_auto_enabled FROM flash_sale_settings WHERE id=1;"
        );
        if (!settingsRes.rows[0].is_auto_enabled) {
          return;
        }

        const now = Math.floor(Date.now() / 1000);

        // Check for active flash sale
        const activeRes = await pool.query(
          `SELECT * FROM flashSaleProducts WHERE isactive = true AND end_time > $1 LIMIT 1;`,
          [now]
        );

        if (activeRes.rows.length > 0) {
          return;
        }

        // Get all products
        const productRes = await pool.query(`SELECT * FROM products;`);
        const allProducts = productRes.rows;

        // Candidate filter
        const candidates = allProducts.filter(
          (p) => (p.rating > 4.5 || p.isnew) && p.stock > 30
        );

        if (!candidates.length) {
          return;
        }

        // Random select up to 100
        const autoSelected = candidates
          .sort(() => Math.random() - 0.5)
          .slice(0, 100);

        const minDiscount = 10;
        const maxDiscount = 30;

        let productPayload = [];
        let flashSalePayload = [];

        // ======================
        // 🔹 Variant Logic
        // ======================
        for (const prod of autoSelected) {
          const discount =
            Math.floor(Math.random() * (maxDiscount - minDiscount + 1)) +
            minDiscount;

          let updatedProd = { ...prod, isflashsale: true };
          let flashSaleProd = { ...prod, isflashsale: true, discount };
          let updatedProdVariants = [];
          let flashSaleProdVariants = [];

          if (prod.extras?.variants?.length > 0) {
            // 👉 যদি variant থাকে
            prod.extras.variants.map((variant) => {
              const minStock = variant.stock > 50 ? 40 : 2;
              const maxStock = variant.stock > 50 ? 45 : 5;
              const variantFlashStock =
                Math.floor(Math.random() * (maxStock - minStock + 1)) +
                minStock;
              const newVariantStock = variant.stock - variantFlashStock;

              const variantSalePrice = Math.round(
                (variant.regular_price ?? 0) -
                  ((variant.regular_price ?? 0) * discount) / 100
              );

              // flash sale variant
              flashSaleProdVariants.push({
                ...variant,
                stock: variantFlashStock,
                sale_price: variantSalePrice,
              });

              // main updated product variant
              updatedProdVariants.push({
                ...variant,
                stock: newVariantStock,
              });
            });

            updatedProd = {
              ...updatedProd,
              extras: { ...prod.extras, variants: updatedProdVariants },
              stock: updatedProdVariants.reduce(
                (sum, v) => sum + (v.stock ?? 0),
                0
              ),
            };

            flashSaleProd = {
              ...flashSaleProd,
              extras: { ...prod.extras, variants: flashSaleProdVariants },
              stock: flashSaleProdVariants.reduce(
                (sum, v) => sum + (v.stock ?? 0),
                0
              ),
              sale_price: Math.round(
                prod.regular_price - (prod.regular_price * discount) / 100
              ),
            };

            productPayload.push(updatedProd);
            flashSalePayload.push(flashSaleProd);
          } else {
            // 👉 single product
            const minStock = prod.stock > 50 ? 45 : 3;
            const maxStock = prod.stock > 50 ? 50 : 5;
            const flashSaleStock =
              Math.floor(Math.random() * (maxStock - minStock + 1)) + minStock;
            const newStock = prod.stock - flashSaleStock;
            const salePrice = Math.round(
              (prod.regular_price ?? 0) -
                ((prod.regular_price ?? 0) * discount) / 100
            );

            updatedProd = {
              ...updatedProd,
              stock: newStock,
            };

            flashSaleProd = {
              ...flashSaleProd,
              stock: flashSaleStock,
              sale_price: salePrice,
            };

            productPayload.push(updatedProd);
            flashSalePayload.push(flashSaleProd);
          }
        }

        // Insert new flash sale
        const startTime = now;
        const endTime = now + 24 * 60 * 60; // 24 hours active

        await pool.query(
          `INSERT INTO flashSaleProducts (isactive, start_time, end_time, sale_products)
       VALUES (true, $1, $2, $3);`,
          [startTime, endTime, JSON.stringify(flashSalePayload)]
        );

        await Promise.all(
          productPayload.map(async (p) => {
            const query = `
          UPDATE products SET  product_name=$1, regular_price=$2, sale_price=$3, discount=$4, rating=$5,
                isbestseller=$6, ishot=$7, isnew=$8, istrending=$9, islimitedstock=$10, isexclusive=$11, isflashsale=$12,
                category=$13, subcategory=$14, description=$15, stock=$16, brand=$17, images=$18, extras=$19,
                 updatedAt=$20 WHERE id = $21;
        `;
            const values = [
              p.product_name,
              p.regular_price,
              p.sale_price,
              p.discount,
              p.rating,
              p.isbestseller,
              p.ishot,
              p.isnew,
              p.istrending,
              p.islimitedstock,
              p.isexclusive,
              p.isflashSale,
              p.category,
              p.subcategory,
              p.description,
              p.stock,
              p.brand,
              p.images,
              p.extras,
              p.updatedAt,
              p.id,
            ];
            await pool.query(query, values);
          })
        );
      } catch (err) {
        console.error("❌ Flash sale generation failed:", err.message);
      }
    });

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
            const query = `SELECT id, product_name, category, subcategory, stock, extras
FROM products
WHERE seller_id = $1
ORDER BY stock ASC;
`;
            const result = await pool.query(query, [sellerId]);
            return res.status(200).json({
              message: "Return Inventory Successfully Done",
              inventory: result.rows,
            });
          } else {
            const query =
              "SELECT id,product_name,category,subcategory,stock,extras FROM products WHERE seller_role='super admin';";
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
      }
    );

    // PATCH: Update Inventory Products Stocks
    app.patch(
      "/inventory/:sellerId",
      passport.authenticate("jwt", { session: false }),
      async (req, res) => {
        try {
          const { productId, variantIndex, change } = req.body;
          const { sellerId } = req.params;

          if (
            !productId ||
            variantIndex === undefined ||
            typeof change !== "number"
          ) {
            return res.status(400).json({
              message: "productId, variantIndex & change are required",
            });
          }

          if (req.user.role === "moderator" || req.user.role === "admin") {
            // Fetch product with extras
            const productResult = await pool.query(
              `SELECT id, seller_id, product_name, extras FROM products WHERE id = $1 AND seller_role='super admin'`,
              [productId]
            );

            if (productResult.rows.length === 0) {
              return res.status(404).json({ message: "Product not found" });
            }

            let { seller_id, product_name } = productResult.rows[0];

            let extras = productResult.rows[0].extras;
            let variants = extras.variants || [];

            // Validate variant index
            if (!variants[variantIndex]) {
              return res.status(400).json({ message: "Invalid variant index" });
            }

            // Update stock
            variants[variantIndex].stock = Math.max(
              variants[variantIndex].stock + change,
              0
            );

            const newStock = variants[variantIndex].stock;

            // 🔥 Notification Logic
            if (newStock === 0) {
              await createNotification({
                userId: seller_id,
                userRole: "seller",
                title: "Product Out of Stock",
                message: `${product_name} has run out of stock.`,
                type: "out_of_stock",
                refId: productId,
                refData: { variantIndex, newStock },
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
                refData: { variantIndex, newStock },
                expiresAt: "2d",
              });
            }

            // Recalculate total stock
            const totalStock = variants.reduce((sum, v) => sum + v.stock, 0);

            // Update DB
            const updateResult = await pool.query(
              `
      UPDATE products
      SET extras = $1, stock = $2
      WHERE id = $3
      `,
              [{ variants }, totalStock, productId]
            );

            return res.json({
              message: "Variant & main product stock updated",
              totalStock,
              variants,
              updatedCount: updateResult.rowCount,
            });
          }

          // Fetch product with extras
          const productResult = await pool.query(
            `SELECT id, seller_id, product_name, extras FROM products WHERE id = $1 AND seller_id=$2`,
            [productId, sellerId]
          );

          if (productResult.rows.length === 0) {
            return res.status(404).json({ message: "Product not found" });
          }

          let { seller_id, product_name } = productResult.rows[0];

          let extras = productResult.rows[0].extras;
          let variants = extras.variants || [];

          // Validate variant index
          if (!variants[variantIndex]) {
            return res.status(400).json({ message: "Invalid variant index" });
          }

          // Update stock
          variants[variantIndex].stock = Math.max(
            variants[variantIndex].stock + change,
            0
          );

          const newStock = variants[variantIndex].stock;

          // 🔥 Notification Logic
          if (newStock === 0) {
            await createNotification({
              userId: seller_id,
              userRole: "seller",
              title: "Product Out of Stock",
              message: `${product_name} has run out of stock.`,
              type: "out_of_stock",
              refId: productId,
              refData: { variantIndex, newStock },
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
              refData: { variantIndex, newStock },
              expiresAt: "2d",
            });
          }

          // Recalculate total stock
          const totalStock = variants.reduce((sum, v) => sum + v.stock, 0);

          // Update DB
          const updateResult = await pool.query(
            `
      UPDATE products
      SET extras = $1, stock = $2
      WHERE id = $3
      `,
            [{ variants }, totalStock, productId]
          );

          res.json({
            message: "Variant & main product stock updated",
            totalStock,
            variants,
            updatedCount: updateResult.rowCount,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      }
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

          if (req.user.role === "moderator" || req.user.role === "admin") {
            const { rows: products } = await pool.query(
              "SELECT id, seller_id, product_name, extras, stock FROM products WHERE seller_role='super admin' AND id=$1",
              [productId]
            );

            let updateCount = 0;

            for (let product of products) {
              let extras = product.extras || {};
              let variants = extras.variants || [];
              let totalStock = product.stock;

              if (variants.length > 0) {
                // Update variant stocks
                variants = variants.map((v, index) => {
                  const newStock = Math.max((v.stock || 0) + change, 0);

                  if (newStock === 0) {
                    createNotification({
                      userId: product.seller_id,
                      userRole: "seller",
                      title: "Product Out of Stock",
                      message: `${product.product_name} is OUT OF STOCK.`,
                      type: "out_of_stock",
                      refId: product.id,
                      refData: { variantIndex: index, newStock },
                      expiresAt: "2d",
                    });
                  } else if (newStock <= 5) {
                    createNotification({
                      userId: product.seller_id,
                      userRole: "seller",
                      title: "Low Stock Warning",
                      message: `${product.product_name} LOW STOCK: Only ${newStock} left.`,
                      type: "low_stock",
                      refId: product.id,
                      refData: { variantIndex: index, newStock },
                      expiresAt: "2d",
                    });
                  }

                  return { ...v, stock: newStock };
                });

                totalStock = variants.reduce(
                  (sum, v) => sum + (v.stock || 0),
                  0
                );
                extras.variants = variants;
              } else {
                // No variants, update main stock
                totalStock = Math.max(product.stock + change, 0);

                if (totalStock === 0) {
                  createNotification({
                    userId: product.seller_id,
                    userRole: "seller",
                    title: "Product Out of Stock",
                    message: `${product.product_name} is OUT OF STOCK.`,
                    type: "out_of_stock",
                    refId: product.id,
                    refData: { newStock: totalStock },
                    expiresAt: "7d",
                  });
                } else if (totalStock <= 5) {
                  createNotification({
                    userId: product.seller_id,
                    userRole: "seller",
                    title: "Low Stock Warning",
                    message: `${product.product_name} LOW STOCK: Only ${totalStock} left.`,
                    type: "low_stock",
                    refId: product.id,
                    refData: { newStock: totalStock },
                    expiresAt: "7d",
                  });
                }
              }

              // Save update in DB
              await pool.query(
                `UPDATE products SET extras=$1, stock=$2 WHERE id=$3`,
                [extras, totalStock, product.id]
              );

              updateCount++;
            }

            return res.json({
              updated: true,
              updatedProducts: updateCount,
              message: "All stocks updated successfully",
            });
          }

          // Load products
          const { rows: products } = await pool.query(
            "SELECT id, seller_id, product_name, extras, stock FROM products WHERE seller_id=$1 AND id=$2",
            [sellerId, productId]
          );

          let updateCount = 0;

          for (let product of products) {
            let extras = product.extras || {};
            let variants = extras.variants || [];
            let totalStock = product.stock;

            if (variants.length > 0) {
              // Update variant stocks
              variants = variants.map((v, index) => {
                const newStock = Math.max((v.stock || 0) + change, 0);

                if (newStock === 0) {
                  createNotification({
                    userId: product.seller_id,
                    userRole: "seller",
                    title: "Product Out of Stock",
                    message: `${product.product_name} is OUT OF STOCK.`,
                    type: "out_of_stock",
                    refId: product.id,
                    refData: { variantIndex: index, newStock },
                    expiresAt: "7d",
                  });
                } else if (newStock <= 5) {
                  createNotification({
                    userId: product.seller_id,
                    userRole: "seller",
                    title: "Low Stock Warning",
                    message: `${product.product_name} LOW STOCK: Only ${newStock} left.`,
                    type: "low_stock",
                    refId: product.id,
                    refData: { variantIndex: index, newStock },
                    expiresAt: "7d",
                  });
                }

                return { ...v, stock: newStock };
              });

              totalStock = variants.reduce((sum, v) => sum + (v.stock || 0), 0);
              extras.variants = variants;
            } else {
              // No variants, update main stock
              totalStock = Math.max(product.stock + change, 0);

              if (totalStock === 0) {
                createNotification({
                  userId: product.seller_id,
                  userRole: "seller",
                  title: "Product Out of Stock",
                  message: `${product.product_name} is OUT OF STOCK.`,
                  type: "out_of_stock",
                  refId: product.id,
                  refData: { newStock: totalStock },
                  expiresAt: "7d",
                });
              } else if (totalStock <= 5) {
                createNotification({
                  userId: product.seller_id,
                  userRole: "seller",
                  title: "Low Stock Warning",
                  message: `${product.product_name} LOW STOCK: Only ${totalStock} left.`,
                  type: "low_stock",
                  refId: product.id,
                  refData: { newStock: totalStock },
                  expiresAt: "7d",
                });
              }
            }

            // Save update in DB
            await pool.query(
              `UPDATE products SET extras=$1, stock=$2 WHERE id=$3`,
              [extras, totalStock, product.id]
            );

            updateCount++;
          }

          res.json({
            updated: true,
            updatedProducts: updateCount,
            message: "All stocks updated successfully",
          });
        } catch (err) {
          res.status(500).json({ message: err.message });
        }
      }
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
          const uploadDir = path.join(__dirname, "uploads", "sellers");
          if (!fs.existsSync(uploadDir))
            fs.mkdirSync(uploadDir, { recursive: true });

          const saveMulterImage = async (file, prefix) => {
            if (!file) return null;
            const safeName =
              sellerInfo.full_Name?.replace(/\s+/g, "_") || "seller";
            const filename = `${safeName}_${prefix}_${uuidv4()}.webp`;
            const filepath = path.join(uploadDir, filename);
            await sharp(file.buffer).webp({ lossless: true }).toFile(filepath);
            return `/uploads/sellers/${filename}`;
          };

          const profileImgPath = await saveMulterImage(
            files?.profileImg?.[0],
            "profile"
          );
          const nidFrontPath = await saveMulterImage(
            files?.nidFrontImg?.[0],
            "nid_front"
          );
          const nidBackPath = await saveMulterImage(
            files?.nidBackImg?.[0],
            "nid_back"
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
      }
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
          const uploadDir = path.join(__dirname, "uploads", "sellers");
          if (!fs.existsSync(uploadDir))
            fs.mkdirSync(uploadDir, { recursive: true });

          const saveMulterImage = async (file, prefix) => {
            if (!file) return null;
            const safeName =
              sellerInfo.full_Name?.replace(/\s+/g, "_") || "seller";
            const filename = `${safeName}_${prefix}_${uuidv4()}.webp`;
            const filepath = path.join(uploadDir, filename);
            await sharp(file.buffer).webp({ lossless: true }).toFile(filepath);
            return `/uploads/sellers/${filename}`;
          };

          const profileImgPath = await saveMulterImage(
            files?.profileImg?.[0],
            "profile"
          );
          const nidFrontPath = await saveMulterImage(
            files?.nidFrontImg?.[0],
            "nid_front"
          );
          const nidBackPath = await saveMulterImage(
            files?.nidBackImg?.[0],
            "nid_back"
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
            [email, otp, expiresAt, JSON.stringify(tempData)]
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
`
          );

          return res.status(200).json({
            message: "OTP sent to your email",
            otp_required: true,
          });
        } catch (error) {
          res.status(500).json({ message: "Internal server error" });
        }
      }
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
            [sellerId]
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
            payload.full_name || oldSeller.full_name
          );

          const store_imgPath = await saveMulterImage(
            files?.storeImg?.[0],
            "store",
            payload.store_name || oldSeller.store_name
          );

          const nid_front_filePath = await saveMulterImage(
            files?.nidFrontImg?.[0],
            "nid_front",
            payload.full_name || oldSeller.full_name
          );

          const nid_back_filePath = await saveMulterImage(
            files?.nidBackImg?.[0],
            "nid_back",
            payload.full_name || oldSeller.full_name
          );

          // Password hash
          let hashedPassword = oldSeller.password;
          if (payload.old_password && payload.new_password) {
            const match = await bcrypt.compare(
              payload.old_password,
              oldSeller.password
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

          return res.status(200).json({
            message: "Seller updated successfully",
            seller: result.rows[0],
            updatedCount: result.rowCount,
          });
        } catch (error) {
          res.status(500).json({ message: "Internal server error" });
        }
      }
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
          [updatedReviews, id]
        );

        // Admin টেবিলে আপডেট
        const adminResult = await pool.query(
          "UPDATE admins SET reviews = $1 WHERE id = $2",
          [updatedReviews, id]
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
      }
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
      }
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
          process.env.REFRESH_TOKEN_SECRET
        );
        const newAccessToken = jwt.sign(
          { id: payload.id, email: payload.email, role: payload.role },
          process.env.JWT_SECRET_KEY,
          { expiresIn: "7d" }
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
        });

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
          }
        );

        res
          .cookie("Token", accessToken, {
            httpOnly: true,
            secure: true,
            sameSite: "None",
            domain: ".bazarigo.com",
          })
          .cookie("RefreshToken", refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: "None",
            domain: ".bazarigo.com",
          })
          .redirect(`${process.env.BASEURL}${redirectPath}`);
      }
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
          [userInfo.email]
        );

        if (checkUser.rows.length > 0) {
          return res.status(400).json({ message: "User Already Exists" });
        }

        // Handle profile image
        let profile_imgPath = null;
        if (file) {
          const uploadDir = path.join(__dirname, "uploads", "users");
          if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
          }

          const safeName = (userInfo.name || "user").replace(/\s+/g, "_");
          const filename = `${safeName}_profile_${uuidv4()}.webp`;
          const filepath = path.join(uploadDir, filename);
          await sharp(file.buffer).webp({ lossless: true }).toFile(filepath);
          profile_imgPath = `/uploads/users/${filename}`;
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
          [userInfo.email]
        );
        if (checkUser.rows.length > 0) {
          return res.status(400).json({ message: "User Already Exists" });
        }

        // Handle profile image
        let profile_imgPath = null;
        if (file) {
          const uploadDir = path.join(__dirname, "uploads", "users");
          if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
          }

          const safeName = (userInfo.name || "user").replace(/\s+/g, "_");
          const filename = `${safeName}_profile_${uuidv4()}.webp`;
          const filepath = path.join(uploadDir, filename);
          await sharp(file.buffer).webp({ lossless: true }).toFile(filepath);
          profile_imgPath = `/uploads/users/${filename}`;
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
          [userInfo.email, otp, expiresAt, JSON.stringify(tempData)]
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
`
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
        const { email, password } = req.body;

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
          [new Date(), user.id]
        );

        // Generate OTP
        const otp = crypto.randomInt(100000, 999999).toString();
        const expiresAt = new Date(Date.now() + 60 * 1000);

        // Remove old OTP
        await pool.query("DELETE FROM email_otps WHERE email=$1", [email]);

        // Save OTP
        await pool.query(
          "INSERT INTO email_otps (email, otp, expires_at) VALUES ($1,$2,$3)",
          [email, otp, expiresAt]
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
  `
        );

        return res
          .status(200)
          .json({ message: "OTP sent to your email", otp_required: true });
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
          [email, otp]
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
          [email, otp]
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
                })
              )
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
          [email, otp]
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
          [email]
        );
        if (resultUser.rows.length > 0) {
          user = resultUser.rows[0];
          role = user.role || "moderator";
        }

        if (!user) {
          resultUser = await pool.query(
            "SELECT * FROM sellers WHERE email=$1",
            [email]
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
          }
        );

        res
          .cookie("Token", accessToken, {
            httpOnly: true,
            secure: true,
            sameSite: "None",
            domain: ".bazarigo.com",
          })
          .cookie("RefreshToken", refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: "None",
            domain: ".bazarigo.com",
          })
          .status(200)
          .json({
            message: "Login successful",
            login: true,
            role,
          });
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
          [email, otp, expiresAt]
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
  `
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
            [email]
          );

          res.json(result.rows[0]);
        } catch (err) {
          console.error(err);
          res.status(500).json({ message: err.message });
        }
      }
    );

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
    });

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
              "_"
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
              oldUser.password
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
              [userId]
            );
            if (ordersResult.rows.length > 0) {
              await pool.query(
                `UPDATE orders SET customer_name = $1, customer_email = $2 WHERE customer_id = $3`,
                [
                  payload.full_name || oldUser.name,
                  payload.email || oldUser.email,
                  userId,
                ]
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
      }
    );

    // GET: Get Users API Route
    app.get(
      "/users",
      passport.authenticate("jwt", { session: false }),
      verifyAdmin,
      async (req, res) => {
        try {
          // const query = "SELECT * FROM users;";
          const query = `
        SELECT u.*, 
               COALESCE(o.order_count, 0) AS orders_count
        FROM users u
        LEFT JOIN (
          SELECT customer_email, COUNT(*) AS order_count
          FROM orders
          GROUP BY customer_email
        ) o ON u.email = o.customer_email;
      `;
          const result = await pool.query(query);
          res.status(200).json({
            message: "Users route is working!",
            users: result.rows,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      }
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
      }
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
            "DELETE FROM wishlist WHERE user_email=$1 AND productId=$2";
          const deleteResult = await pool.query(deleteQuery, [
            email,
            productId,
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
            "SELECT * FROM wishlist WHERE user_email=$1 AND productId=$2;";
          const result = await pool.query(query, [email, id]);

          return res.status(200).json({
            message: "Check Is In Wishlist !",
            isInWishlist: result.rows.length > 0,
          });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      }
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
      }
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
      SELECT f.user_id,s.id AS seller_id,s.store_name AS seller_store_name, s.full_name AS seller_full_name, s.email AS seller_email
      FROM following f
      JOIN sellers s ON f.seller_id = s.id
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
      }
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
            (p) => !existingProductIds.includes(p.product_Id)
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
        WHERE cartId = $2
      `;
          const updateCartResult = await pool.query(updateCartQuery, [
            JSON.stringify(updatedCart),
            existingCart.cartid,
          ]);

          res.status(200).json({
            message: "Cart updated successfully!",
            updatedCount: updateCartResult.rowCount,
          });
        } else {
          const insertCartQuery = `
        INSERT INTO carts (cartId,user_email,sellerId,productInfo,deliveries)
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
            insertCartQueryValues
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
          //       const query = `
          //   SELECT
          //     c.*,
          //     COALESCE(s.full_name, a.full_name) AS seller_name,
          //     COALESCE(s.store_name, a.store_name) AS seller_store_name
          //   FROM carts c
          //   LEFT JOIN sellers s ON c.sellerid = s.id
          //   LEFT JOIN admins a ON c.sellerid = a.id
          //   WHERE c.user_email = $1;
          // `;
          const query = `
      SELECT 
    c.*,
    COALESCE(s.full_name, a.full_name) AS seller_name,
    COALESCE(s.store_name, a.store_name) AS seller_store_name,
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
      }
    );

    // PATCH Add deliveries
    app.patch("/carts", async (req, res) => {
      try {
        const { deliveries, cartId } = req.body;

        const query =
          "UPDATE carts SET deliveries = $1 WHERE cartid = $2 RETURNING *";
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
        const selectQuery = "SELECT productinfo FROM carts WHERE cartid = $1";
        const cartResult = await pool.query(selectQuery, [cartId]);

        if (cartResult.rowCount === 0) {
          return res.status(404).json({ message: "Cart not found" });
        }

        const productInfo = cartResult.rows[0].productinfo;

        // Step 2: Update qty inside JSON in JS
        const updatedInfo = productInfo.map((item) =>
          item.product_Id === productId ? { ...item, qty: newQty } : item
        );

        // Step 3: Save updated JSON back to DB
        const updateQuery =
          "UPDATE carts SET productinfo = $1 WHERE cartid = $2 RETURNING *";
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
        const selectQuery = "SELECT * FROM carts WHERE cartid = $1";
        const cartResult = await pool.query(selectQuery, [cartId]);

        if (cartResult.rowCount === 0) {
          return res.status(404).json({ message: "Cart not found" });
        }

        const cart = cartResult.rows[0];
        const productInfo = cart.productinfo;

        // Step 2: Filter out the product to remove
        const updatedInfo = productInfo.filter(
          (item) => item.product_Id !== productId
        );

        // Step 3: যদি সব প্রোডাক্ট বাদ পড়ে যায় → পুরো cart মুছে ফেল
        if (updatedInfo.length === 0) {
          const deleteQuery = "DELETE FROM carts WHERE cartid = $1";
          const deletedResult = await pool.query(deleteQuery, [cartId]);
          return res.status(200).json({
            message: "Product removed and cart deleted (empty now).",
            deletedCount: deletedResult.rowCount,
          });
        }

        // Step 4: অন্যথায় শুধু আপডেট করো
        const updateQuery =
          "UPDATE carts SET productinfo = $1 WHERE cartid = $2 RETURNING *";
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
            (p) => !ids.includes(p.product_Id)
          );

          if (updatedProducts.length === 0) {
            const deleteResult = await pool.query(
              "DELETE FROM carts WHERE cartid = $1",
              [cart.cartid]
            );
            res.status(200).json({
              message: "Products deleted successfully",
              deletedCount: deleteResult.rowCount,
            });
          } else {
            const updatedResult = await pool.query(
              "UPDATE carts SET productinfo = $1 WHERE cartid = $2",
              [JSON.stringify(updatedProducts), cart.cartid]
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
      }
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
              zone.is_remote || false
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
      }
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
            [sellerId]
          );
          let sellerPostalCode = null;

          if (adminCheck.rows.length > 0) {
            if (
              adminCheck.rows[0].role === "admin" ||
              adminCheck.rows[0].role === "moderator"
            ) {
              const bazarigo = await pool.query(
                "SELECT postal_code FROM admins WHERE email='bazarigo.official@gmail.com'"
              );
              sellerPostalCode = bazarigo.rows[0]?.postal_code || "1212"; // default postal code
            } else {
              sellerPostalCode = adminCheck.rows[0].postal_code;
            }
          } else {
            const sellerCheck = await pool.query(
              "SELECT role, postal_code FROM sellers WHERE id=$1",
              [sellerId]
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
    CASE
      WHEN ($4 * 1.01) >= COALESCE(z.free_delivery_min_amount, 999999) THEN 0
      ELSE GREATEST(
        CASE
          WHEN zc.zone_name = 'Inside Area' THEN 70
          WHEN zc.zone_name = 'Near Area' THEN 100
          WHEN zc.zone_name = 'Outside Area' THEN 120
          WHEN zc.zone_name = 'Remote Area' THEN 200
          ELSE 0
        END,
        ( z.delivery_charge + (GREATEST(COALESCE(NULLIF($3, '')::numeric, 1), 0) * 10) + CASE WHEN $5 = 'true' THEN GREATEST(10, $4 * 0.01) ELSE 0 END )
      )
    END AS INTEGER
  ) AS total_delivery_charge
FROM zone_calc zc
LEFT JOIN zones z ON z.name = zc.zone_name;
`;

          const result = await pool.query(query, [
            sellerPostalCode, // $1
            userId,
            weight,
            orderAmount,
            isCodBool,
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
      }
    );

    // ------------ Delivery API Routes End ----------------//

    // ------------ Orders API Routes ----------------//
    // POST: Create Order API Route

    app.post("/orders", async (req, res) => {
      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        const { payload, promoCode, userId, paymentPayload } = req.body;
        const orderId = generateId("OR");

        const orderdProducts = payload.orderItems.flatMap((item) =>
          item.productinfo.map((prod) => ({
            product_id: prod.product_Id,
            variants: prod.variants,
            qty: prod.qty,
            isflashsale: prod.isflashsale,
            sellerid: item.sellerid,
          }))
        );

        // ফাংশন: Flash Sale Stock Update
        const updateFlashSaleStock = async (item) => {
          const now = Math.floor(Date.now() / 1000);
          const flashRes = await client.query(
            `SELECT id, sale_products FROM flashSaleProducts WHERE isactive = true AND start_time <= $1 AND end_time >= $1`,
            [now]
          );
          if (!flashRes.rows.length) return;

          const flashSale = flashRes.rows[0];
          let updated = false;

          for (const sp of flashSale.sale_products) {
            if (sp.id !== item.product_id) continue;
            const variantsArr = sp.extras?.variants || [];
            const variantIndex = variantsArr.findIndex((v) =>
              Object.keys(item.variants).every((k) => v[k] === item.variants[k])
            );
            if (variantIndex === -1) continue;

            variantsArr[variantIndex].stock = Math.max(
              variantsArr[variantIndex].stock - item.qty,
              0
            );
            sp.stock = variantsArr.reduce((sum, v) => sum + (v.stock || 0), 0);
            updated = true;
            break;
          }

          if (updated) {
            await client.query(
              `UPDATE flashSaleProducts SET sale_products = $1 WHERE id = $2`,
              [JSON.stringify(flashSale.sale_products), flashSale.id]
            );
          }
        };

        // ফাংশন: Normal Product Stock Update + Notifications
        const updateNormalStock = async (item) => {
          const productRes = await client.query(
            `SELECT id, seller_id, product_name, extras FROM products WHERE id = $1`,
            [item.product_id]
          );
          if (!productRes.rows.length) return;

          let { seller_id, product_name, extras } = productRes.rows[0];
          let variants = extras.variants || [];

          const variantIndex = variants.findIndex((v) =>
            Object.keys(item.variants).every((k) => v[k] === item.variants[k])
          );
          if (variantIndex === -1) return;

          variants[variantIndex].stock = Math.max(
            variants[variantIndex].stock - item.qty,
            0
          );
          const newStock = variants[variantIndex].stock;

          // Notification
          const notifications = [];
          if (newStock === 0) notifications.push({ type: "out_of_stock" });
          else if (newStock <= 5) notifications.push({ type: "low_stock" });

          if (notifications.length) {
            await Promise.all(
              notifications.map((n) =>
                createNotification({
                  userId: seller_id,
                  userRole: "seller",
                  title:
                    n.type === "out_of_stock"
                      ? "Product Out of Stock"
                      : "Low Stock Warning",
                  message: `${product_name} (${JSON.stringify(
                    item.variants
                  )}) ${
                    n.type === "out_of_stock"
                      ? "is now OUT OF STOCK."
                      : "stock is low. Only " + newStock + " left."
                  }`,
                  type: n.type,
                  refId: item.product_id,
                  expiresAt: "7d",
                })
              )
            );
          }

          const totalStock = variants.reduce((sum, v) => sum + v.stock, 0);
          await client.query(
            `UPDATE products SET extras = $1, stock = $2 WHERE id = $3`,
            [{ variants }, totalStock, item.product_id]
          );
        };

        // Stock update for all products concurrently
        await Promise.all(
          orderdProducts.map((item) =>
            item.isflashsale
              ? updateFlashSaleStock(item)
              : updateNormalStock(item)
          )
        );

        // Insert order
        const query = `INSERT INTO orders (order_id,order_date,payment_method,payment_status,customer_id,customer_name,customer_email,customer_phone,customer_address,order_items,subtotal,delivery_cost,total) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *;`;
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

        // Promo code handling
        if (promoCode) {
          const promoRes = await client.query(
            `SELECT id FROM promotions WHERE code=$1`,
            [promoCode]
          );
          if (promoRes.rows.length) {
            await client.query(
              `UPDATE user_promotions SET used=true WHERE user_id=$1 AND promo_id=$2`,
              [userId, promoRes.rows[0].id]
            );
          }
        }

        // Delete items from carts
        const cartDeletes = payload.orderItems.map((item) =>
          client.query(
            `DELETE FROM carts WHERE cartid = $1 AND user_email = $2`,
            [item.cartid, item.user_email]
          )
        );
        await Promise.all(cartDeletes);

        // Payment insert
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
          ]
        );

        // Seller notifications
        await Promise.all(
          result.rows[0].order_items.map(async (item) => {
            const getSeller = await client.query(
              `
        SELECT id,role FROM admins WHERE id = $1
        UNION
        SELECT id,role FROM sellers WHERE id = $1
      `,
              [item.sellerid]
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
          })
        );

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
          const uploadDir = path.join(__dirname, "uploads", "returns");
          if (!fs.existsSync(uploadDir))
            fs.mkdirSync(uploadDir, { recursive: true });

          // Save uploaded files to WebP
          const savedPaths = await Promise.all(
            files.map(async (file, i) => {
              const filename = `${customer_name}-${i}-${uuidv4()}.webp`;
              const filepath = path.join(uploadDir, filename);

              await sharp(file.buffer)
                .webp({ lossless: true })
                .toFile(filepath);
              return `/uploads/returns/${filename}`;
            })
          );

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
                })
              )
            );

            return res.status(201).json({
              message: "Return Request submitted successfully",
              createdCount: result.rowCount,
            });
          }
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      }
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
      }
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
      }
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
      }
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
      }
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
        const { order_status, prodId } = req.body;

        const orderQuery = `SELECT customer_id,order_items FROM orders WHERE order_id=$1`;
        const orderRes = await pool.query(orderQuery, [id]);

        if (!orderRes.rows.length) {
          return res.status(404).json({ message: "Order not found" });
        }

        const orderItems = orderRes.rows[0].order_items;
        let returnedQty = 0;

        // 2️⃣ Get customer info + reason from return_requests (only if returned)
        let returnReason = "";
        let customerId = null;
        let customerName = "";
        let images = [];
        if (order_status === "Returned") {
          const reasonQuery = `
        SELECT customer_id, customer_name, reason ,images
        FROM return_requests
        WHERE order_id=$1
        LIMIT 1
      `;
          const reasonRes = await pool.query(reasonQuery, [id]);
          if (reasonRes.rows.length) {
            returnReason = reasonRes.rows[0].reason;
            customerId = reasonRes.rows[0].customer_id;
            customerName = reasonRes.rows[0].customer_name;
            images = reasonRes.rows[0].images;
          }
        }
        if (order_status === "Returned") {
          const returnedProducts = orderItems.flatMap((item) => {
            const returnProduct = item.productinfo.find(
              (prod) => prod.product_Id === prodId
            );
            return {
              ...returnProduct,
              sellerid: item.sellerid,
              product_img: [...images],
            };
          });

          if (returnedProducts.length > 0) {
            const insertQuery = `
            INSERT INTO return_orders (id,order_id, customer_id, customer_name, products, reason, status,created_at)
            VALUES ($1, $2, $3, $4, $5, $6,$7, NOW())
          `;
            const returnResult = await pool.query(insertQuery, [
              generateId("RO"),
              id,
              customerId,
              customerName,
              JSON.stringify(returnedProducts),
              returnReason || "No reason provided",
              "Returned",
            ]);

            /* 🔔 Notify customer about status change */
            if (returnResult.rowCount > 0) {
              const sellerId = updatedOrderItems[0].sellerid;
              await createNotification({
                userId: customerId,
                userRole: "customer",
                title: "Order Returned",
                message: `A product in order ${id} has been returned.".`,
                type: "order",
                refId: id,
                expiresAt: "7d",
              });

              /* 🔔 Notify seller (if exists) */
              if (sellerId) {
                await createNotification({
                  userId: sellerId,
                  userRole: "seller",
                  title: "Order Returned",
                  message: `A product in order ${id} has been returned.".`,
                  type: "order",
                  refId: id,
                  expiresAt: "7d",
                });
              }
            }
          }
        }

        // 3️⃣ Update order_items
        const updatedOrderItems = orderItems.map((item) => {
          let updatedProducts = item.productinfo.map((prod) => {
            if (prod.product_Id === prodId) {
              if (order_status === "Cancelled" || order_status === "Returned") {
                returnedQty = prod.qty;
                prod.variants.stock += prod.qty; // stock update
              } else {
                prod.order_status = order_status;
              }
            }
            return prod;
          });

          if (order_status === "Cancelled" || order_status === "Returned") {
            updatedProducts = updatedProducts.filter(
              (prod) => prod.product_Id !== prodId
            );
          }

          return { ...item, productinfo: updatedProducts };
        });

        // 🔥 নতুন অংশ: যদি সব product খালি হয়ে যায় → order delete
        const productsRemaining = updatedOrderItems.some(
          (item) => item.productinfo.length > 0
        );

        customerId = orderRes.rows[0].customer_id;

        if (!productsRemaining) {
          const deleteQuery = `DELETE FROM orders WHERE order_id=$1`;
          const deleteOrder = await pool.query(deleteQuery, [id]);

          if (deleteOrder.rowCount > 0) {
            const sellerId = updatedOrderItems[0].sellerid;
            /* 🔔 Notify customer about status change */
            await createNotification({
              userId: customerId,
              userRole: "customer",
              title: "Order Update",
              message: `Your order status changed to "${order_status}".`,
              type: "order",
              refId: id,
              expiresAt: "7d",
            });

            /* 🔔 Notify seller (if exists) */
            if (sellerId) {
              await createNotification({
                userId: sellerId,
                userRole: "seller",
                title: "Order Update",
                message: `One of your products in order ${id} is now "${order_status}".`,
                type: "order",
                refId: id,
                expiresAt: "7d",
              });
            }
            return res.json({
              message: "Order deleted because no products left",
              deleted: true,
              deletedCount: deleteOrder.rowCount,
            });
          }
        }

        // আগের মতোই update
        const updateQuery = `UPDATE orders SET order_items=$1 WHERE order_id=$2`;
        const updatedResult = await pool.query(updateQuery, [
          JSON.stringify(updatedOrderItems),
          id,
        ]);

        if (updatedResult.rowCount > 0) {
          const sellerId = updatedOrderItems[0].sellerid;

          /* 🔔 Notify customer about status change */
          await createNotification({
            userId: customerId,
            userRole: "customer",
            title: "Order Update",
            message: `Your order status changed to "${order_status}".`,
            type: "order",
            refId: id,
            expiresAt: "7d",
          });

          /* 🔔 Notify seller (if exists) */
          if (sellerId) {
            await createNotification({
              userId: sellerId,
              userRole: "seller",
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
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // PATCH: Update Return Request Status
    app.patch("/return-requests/status/:id", async (req, res) => {
      try {
        const { id } = req.params;
        const { status } = req.body;

        if (status === "rejected") {
          const deleteQuery =
            "DELETE FROM return_requests WHERE id = $1 RETURNING *;";
          const deleteResult = await pool.query(deleteQuery, [id]);
          if (deleteResult.rowCount > 0) {
            const getUserFromOrder = await pool.query(
              `
  SELECT u.id, u.role
  FROM orders o
  JOIN users u ON o.customer_id = u.id
  WHERE o.order_id = $1
`,
              [deleteResult.rows[0].order_id]
            );

            await createNotification({
              userId: getUserFromOrder.rows[0].id,
              userRole: getUserFromOrder.rows[0].role,
              title: "Return Request Rejected",
              message: `A return request was submitted for Order ID: ${deleteResult.rows[0].order_id}`,
              type: "return_request",
              refId: deleteResult.rows[0].order_id,
              expiresAt: "7d",
            });
            return res.status(200).json({
              message: "Return Request rejected and deleted successfully",
              deletedCount: deleteResult.rowCount,
            });
          }
        }
        const query =
          "UPDATE return_requests SET status=$1 WHERE id = $2 RETURNING *;";
        const values = [status, id];
        const result = await pool.query(query, values);
        if (result.rowCount > 0) {
          const getUserFromOrder = await pool.query(
            `
  SELECT u.id, u.role
  FROM orders o
  JOIN users u ON o.customer_id = u.id
  WHERE o.order_id = $1
`,
            [result.rows[0].order_id]
          );

          await createNotification({
            userId: getUserFromOrder.rows[0].id,
            userRole: getUserFromOrder.rows[0].role,
            title: "Return Request Approved",
            message: `A return request was submitted for Order ID: ${result.rows[0].order_id}`,
            type: "return_request",
            refId: result.rows[0].order_id,
            expiresAt: "7d",
          });
          return res.status(200).json({
            message: "Return Request status updated successfully",
            updatedCount: result.rowCount,
          });
        }
      } catch (error) {
        res.status(500).json({ message: error.message });
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
      }
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
      }
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
      }
    );
    // GET: Get Return Order By email API Route
    app.get(
      "/return-requests/:email",
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
      }
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
      }
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
      }
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
      }
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
      }
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
      }
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
          [code]
        );

        if (promoResult.rows.length === 0)
          return res.status(400).json({ message: "Invalid  promo" });

        const promo = promoResult.rows[0];

        // Check if already used
        const usedCheck = await pool.query(
          "SELECT * FROM user_promotions WHERE user_id=$1 AND promo_id=$2 AND used=true",
          [userId, promo.id]
        );
        if (usedCheck.rows.length > 0)
          return res.status(400).json({ message: "Already Used Promo!" });

        // Record promo as unused initially
        await pool.query(
          "INSERT INTO user_promotions (user_id, promo_id, used) VALUES ($1,$2,false) RETURNING *",
          [userId, promo.id]
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
            `SELECT p.code, p.discount, up.id as user_promo_id
       FROM user_promotions up
       JOIN promotions p ON up.promo_id = p.id
       WHERE up.user_id=$1 AND up.used=false`,
            [userId]
          );
          res.json({ promo: result.rows[0] || null });
        } catch (err) {
          res.status(500).json({ message: err.message });
        }
      }
    );

    // Mark Promo as Used (Order Complete)
    app.patch("/user-promotions/:userId/:promoId/use", async (req, res) => {
      try {
        const { userId, promoId } = req.params;
        const result = await pool.query(
          "UPDATE user_promotions SET used=true WHERE user_id=$1 AND promo_id=$2 RETURNING *",
          [userId, promoId]
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
       LIMIT 1`
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
      }
    );

    // Send message

    app.post("/send", async (req, res) => {
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

        // মূল message insert
        const result = await pool.query(
          `INSERT INTO messages (id, sender_id, sender_role, receiver_id, receiver_role, content)
           VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
          [id, sender_id, sender_role, receiver_id, receiver_role, content]
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
                ]
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
            [otherUserId, loggedInUserId]
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
            [loggedInUserId, otherUserId]
          );

          res.status(200).json({ success: true, messages: result.rows });
        } catch (err) {
          res.status(500).json({ success: false, error: err.message });
        }
      }
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
      }
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
      }
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
      }
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
            [adminId]
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
            payload.full_name || oldAdmin.full_name
          );

          const store_imgPath = await saveMulterImage(
            files?.storeImg?.[0],
            "store",
            payload.store_name || oldAdmin.store_name
          );

          // Password hash handle
          let hashedPassword = oldAdmin.password;

          if (payload.old_password && payload.new_password) {
            const match = await bcrypt.compare(
              payload.old_password,
              oldAdmin.password
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
            payload.product_category || oldAdmin.product_category,
            payload.business_address || oldAdmin.business_address,
            adminId,
          ];

          const result = await pool.query(query, values);

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
      }
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
          const totalSalesQuery = `SELECT SUM(amount) as total_sales FROM payments`;
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
      }
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

          const customerSet = new Set();
          const sellerMap = new Map();
          const categoryMap = new Map();
          const productMap = new Map();
          const productCommissionMap = new Map();
          const ordersByDayMap = new Map();

          // -------------------- INIT DATE MAP --------------------
          if (interval === "weekly") {
            ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].forEach((day) =>
              ordersByDayMap.set(day, 0)
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

                // Category
                categoryMap.set(
                  category,
                  (categoryMap.get(category) || 0) + qty
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
            })
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
            })
          );

          const productCommissionData = Array.from(
            productCommissionMap.values()
          );
          const sellerCommissionData = Array.from(sellerMap.values());

          return res.json({
            reportType: interval,
            totalOrders,
            orders,
            revenue,
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
      }
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
            [sellerId]
          );

          // -----------------------------
          // 2️⃣ Seller Profile
          // -----------------------------
          const sellerProfile = await pool.query(
            `SELECT id, full_name, email, store_name, img, district, thana 
       FROM sellers
       WHERE id = $1`,
            [sellerId]
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
            [sellerId]
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
            [sellerId]
          );

          // -----------------------------
          // 6️⃣ Inventory / Low stock items
          // -----------------------------
          const lowStock = products.rows.filter((p) => p.stock < 1000);

          // -----------------------------
          // 7️⃣ Sales Trend (Last 7 Days)
          // -----------------------------
          //         const salesTrendQuery = `
          //   SELECT
          //       TO_CHAR(order_date::date, 'YYYY-MM-DD') AS date,
          //       COALESCE(
          //           SUM(
          //               (
          //                   CASE
          //                       WHEN (prod->>'sale_price')::int > 0
          //                       THEN (prod->>'sale_price')::int
          //                       ELSE (prod->>'regular_price')::int
          //                   END
          //               ) * (prod->>'qty')::int
          //           ), 0
          //       ) AS revenue
          //   FROM orders o,
          //   jsonb_array_elements(o.order_items) AS item,
          //   jsonb_array_elements(item->'productinfo') AS prod
          //   WHERE item->>'sellerid' = $1
          //     AND o.order_date >= NOW() - INTERVAL '7 days'
          //   GROUP BY order_date::date
          //   ORDER BY date ASC;
          // `;
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
            [sellerId]
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
      }
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
                orderDate.getMonth() + 1
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
                  categoryMap.get(category) + sellerEarnings
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
            { totalSales: 0, totalCommission: 0, totalEarnings: 0 }
          );

          return res.json({
            revenueByInterval: Array.from(revenueMap.values()).sort((a, b) =>
              a.key.localeCompare(b.key)
            ),
            categorySales: Array.from(categoryMap.entries()).map(
              ([name, value], i) => ({
                name,
                value,
                color: ["#4F46E5", "#10B981", "#F59E0B", "#EF4444", "#8B5CF6"][
                  i % 5
                ],
              })
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
      }
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
      }
    );
    cron.schedule("* * * * *", async () => {
      try {
        const { rows } = await pool.query(
          `SELECT id, created_at, expires_at FROM notifications WHERE expires_at IS NOT NULL`
        );
        const now = new Date();

        for (const row of rows) {
          const durationMs = parseDuration(row.expires_at);
          const expireTime = new Date(
            new Date(row.created_at).getTime() + durationMs
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
      }
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
  res.send(`Welcome to Bazarigo Server! ${process.env.DATABASE_PORT}`);
});

app.listen(port, async () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
