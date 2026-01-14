

-- Products Table

CREATE TABLE banner (
id VARCHAR(255) PRIMARY KEY,
link TEXT,
image TEXT
);

CREATE TABLE products (
    id VARCHAR(255) PRIMARY KEY,
    product_name VARCHAR(255) NOT NULL,
    regular_price INT DEFAULT 0,
    sale_price INT NOT NULL,
    discount INT DEFAULT 0,
    rating NUMERIC(2,1),
    isBestSeller BOOLEAN DEFAULT FALSE,
    isHot BOOLEAN DEFAULT FALSE,
    isNew BOOLEAN DEFAULT TRUE,
    isTrending BOOLEAN DEFAULT FALSE,
    isLimitedStock BOOLEAN DEFAULT FALSE,
    isExclusive BOOLEAN DEFAULT FALSE,
    isFlashSale BOOLEAN DEFAULT FALSE,
    canDeleteByModerator BOOLEAN DEFAULT FALSE,
    category VARCHAR(100),
    subcategory VARCHAR(100),
    subcategory_item VARCHAR(100),
    description TEXT,
    stock INT DEFAULT 0,
    brand VARCHAR(100),
    weight INT DEFAULT 1,
    images TEXT[],
    extras JSONB,
    reviews JSONB[] DEFAULT '{}',
    questions JSONB[] DEFAULT '{}',
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updatedAt TIMESTAMP DEFAULT NULL,
    seller_id VARCHAR(100),
    seller_name VARCHAR(150),
    seller_store_name VARCHAR(150),
    seller_role VARCHAR(50) 
);



-- Flash Sale Products Table
CREATE TABLE flashSaleProducts (
    id SERIAL PRIMARY KEY,
    isActive BOOLEAN DEFAULT FALSE,
    start_time BIGINT,
    end_time BIGINT,  
    sale_products JSONB 
);


-- Sellers Table
CREATE TABLE sellers (
    id VARCHAR(255) PRIMARY KEY,
    full_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    user_name VARCHAR(100) UNIQUE,
    phone_number VARCHAR(50),
    date_of_birth TIMESTAMP,
    gender TEXT,
    img TEXT,
    store_img TEXT,

    nid_number VARCHAR(50),
    store_name VARCHAR(255) DEFAULT NULL,
    product_category VARCHAR(255) DEFAULT NULL,
    business_address TEXT DEFAULT NULL,
    district VARCHAR(100) NOT NULL,
    thana VARCHAR(100) NOT NULL,
    postal_code INT  NOT NULL,
    trade_license_number VARCHAR(50),
    nid_front_file TEXT,        
    nid_back_file TEXT,         
    bank_name VARCHAR(100),
    branch_name VARCHAR(100),
    account_number VARCHAR(50),
    account_holder_name VARCHAR(50),
    routing_number VARCHAR(50),
    mobile_bank_name VARCHAR(100),
    mobile_bank_account_number VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    last_login TIMESTAMP DEFAULT NULL,
    role VARCHAR(50) DEFAULT NULL,
    reviews JSONB[] DEFAULT '{}'

);

-- Users Table
CREATE TABLE users (
  id VARCHAR(255) PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  user_name VARCHAR(100) UNIQUE,
  email VARCHAR(255) NOT NULL UNIQUE,
  img  TEXT DEFAULT NULL,
  phone VARCHAR(50) DEFAULT NULL,
  password VARCHAR(255) ,
  address TEXT DEFAULT NULL,
  district VARCHAR(100) NULL,
  thana VARCHAR(100) NULL,
  postal_code INT DEFAULT NULL,
  date_of_birth TIMESTAMP,
  gender TEXT,
  facebook_id VARCHAR(255) DEFAULT NULL,
  google_id VARCHAR(255) DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT NULL,
  last_login TIMESTAMP DEFAULT NULL,
  role VARCHAR(50) DEFAULT 'customer',
 payment_methods JSONB DEFAULT '{}'

); 


-- Admins Table
CREATE TABLE admins (
    id VARCHAR(255) PRIMARY KEY,
    full_name VARCHAR(255) NOT NULL,
    user_name VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    phone_number VARCHAR(50),
    profile_img TEXT,
    store_img TEXT,

    address TEXT DEFAULT NULL,
    district VARCHAR(100) NULL,
    thana VARCHAR(100) NULL,
    postal_code INT DEFAULT NULL,
    date_of_birth TIMESTAMP,
    gender TEXT,
    role VARCHAR(50) DEFAULT 'admin', 
    permissions JSONB DEFAULT '{}',
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT NULL,
    store_name VARCHAR(255) DEFAULT NULL,
    
    product_category VARCHAR(255) DEFAULT NULL,
    business_address TEXT DEFAULT NULL
);



CREATE TABLE following(
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    seller_id VARCHAR(255) NOT NULL,
    followed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);






CREATE TABLE zones (
  id SERIAL PRIMARY KEY,
  name VARCHAR(50) UNIQUE NOT NULL,
  delivery_time VARCHAR(50),
  delivery_charge INTEGER NOT NULL,
  per_kg_charge INTEGER DEFAULT 10,
  free_delivery_min_amount INTEGER DEFAULT 2500 
);


-- Postal Zones Table
CREATE TABLE postal_zones (
  id SERIAL PRIMARY KEY,
  postal_code INT  NOT NULL,
  division VARCHAR(100) NOT NULL,
  district VARCHAR(100) NOT NULL,
  thana VARCHAR(100) NOT NULL,
  place VARCHAR(100) NOT NULL,
  latitude NUMERIC(9,6) NOT NULL,
  longitude NUMERIC(9,6) NOT NULL,
  is_remote BOOLEAN DEFAULT FALSE
);

-- Orders Table

CREATE TABLE orders (
    order_id VARCHAR(255) PRIMARY KEY,
    order_number SERIAL NOT NULL,
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    payment_method VARCHAR(100),
    payment_status VARCHAR(50) DEFAULT 'pending',
    customer_id VARCHAR(255) NOT NULL,
    customer_name VARCHAR(255) NOT NULL,
    customer_email VARCHAR(255) NOT NULL,
    customer_phone VARCHAR(50),
    customer_address TEXT,
    order_items JSONB NOT NULL,
    subtotal INT NOT NULL,
    delivery_cost INT DEFAULT 0,
    total INT NOT NULL
);

-- Return Orders Table


CREATE TABLE return_orders (
  id VARCHAR(255) PRIMARY KEY,
  order_id VARCHAR(255) NOT NULL,
  customer_id VARCHAR(255) NOT NULL,
  customer_name VARCHAR(255) NOT NULL,
  products JSONB NOT NULL,
  reason TEXT,
  status VARCHAR(50) DEFAULT 'Returned', 
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE return_requests (
  id VARCHAR(255) PRIMARY KEY,
  order_id VARCHAR(255)  NOT NULL,
  reason TEXT  NOT NULL,
  images  TEXT [],
  status VARCHAR(50) DEFAULT 'pending',
  request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  customer_id VARCHAR(255) NOT NULL,
  customer_name VARCHAR(255) NOT NULL,
  customer_email VARCHAR(255) NOT NULL,
  customer_phone VARCHAR(50) NOT NULL,
 product_name VARCHAR(255) NOT NULL
);


CREATE TABLE email_otps (
 id SERIAL PRIMARY KEY,
 email VARCHAR(255) NOT NULL,
 otp VARCHAR(10) NOT NULL,
 expires_at TIMESTAMP NOT NULL,
 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 temp_data JSONB DEFAULT NULL
);

CREATE TABLE notifications (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    user_role VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    type VARCHAR(50) DEFAULT NULL,
    ref_id VARCHAR(255) NOT NULL,
    ref_data JSONB DEFAULT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at VARCHAR(15) DEFAULT NULL
);








-- Payments Table
CREATE TABLE payments (
      id VARCHAR(255) PRIMARY KEY,
      order_id VARCHAR(255) NOT NULL,
      payment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      amount INT NOT NULL,
      payment_method VARCHAR(100),
      status VARCHAR(50) DEFAULT 'pending',
      phone_number VARCHAR(50) DEFAULT NULL
);

-- Payments Table


CREATE TABLE sellerpayments (
    id SERIAL PRIMARY KEY,
    seller_id VARCHAR(255) NOT NULL,
    seller_name VARCHAR(20) NOT NULL,
    seller_store_name VARCHAR(20) NOT NULL,
    amount NUMERIC(10,2) NOT NULL,
    payment_method TEXT NOT NULL,
    mobile_bank_name TEXT,
    transaction_id TEXT,
    mobile_bank_account_number TEXT,
    bank_name TEXT,
    bank_account_holder_name TEXT,
    bank_account_number TEXT,
    payment_date TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'pending'
);





-- Carts Table 


CREATE TABLE carts (
  cart_id VARCHAR(255) PRIMARY KEY,
  user_email VARCHAR(255) NOT NULL,
  sellerId VARCHAR(255) NOT NULL,
  productinfo JSONB,
  deliveries JSONB
);




-- Wishlist Table 
CREATE TABLE wishlist (
  user_email VARCHAR(255) NOT NULL,
  wishlist_id VARCHAR(255) PRIMARY KEY,
  product_id VARCHAR(255) NOT NULL,
  product_name TEXT NOT NULL,
  sale_price INT NOT NULL,
  regular_price INT NOT NULL,
  variants JSONB,
  weight INT DEFAULT 1,
  brand VARCHAR(20),
  qty INT,
  product_category TEXT,
  img TEXT
);


-- Promotions Table
CREATE TABLE promotions (
  id SERIAL PRIMARY KEY,
  code VARCHAR(50) NOT NULL,
  discount INT NOT NULL,
  start_date DATE NOT NULL,
  end_date DATE NOT NULL,
  is_active BOOLEAN DEFAULT FALSE
);
-- User Promotions Table
CREATE TABLE user_promotions (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    promo_id INT NOT NULL,
    used BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT fk_promo FOREIGN KEY(promo_id) REFERENCES promotions(id)
);


CREATE TABLE flash_sale_settings (
    id SERIAL PRIMARY KEY,
    is_auto_enabled BOOLEAN DEFAULT true,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE messages (
    id VARCHAR(255) PRIMARY KEY,
    sender_id VARCHAR(255) NOT NULL,
    sender_role VARCHAR(50) NOT NULL, -- 'admin', 'seller', 'customer'
    receiver_id VARCHAR(255) NOT NULL,
    receiver_role VARCHAR(50) NOT NULL, -- 'admin', 'seller', 'customer'
    content TEXT NOT NULL,
    read_status BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);




