CREATE DATABASE fullstack_exam;
USE fullstack_exam;

CREATE TABLE users (
    id VARCHAR(12) PRIMARY KEY NOT NULL,
    status ENUM('0', '1') NOT NULL DEFAULT '0',
    full_name VARCHAR(50) NOT NULL,
    email VARCHAR(50) NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE activities (
    id VARCHAR(12) PRIMARY KEY NOT NULL,
    user_id VARCHAR(12) NOT NULL,
    type ENUM('login', 'logout') NOT NULL DEFAULT 'login',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE email_verification (
    id VARCHAR(12) PRIMARY KEY NOT NULL,
    user_id VARCHAR(12) NOT NULL,
    status ENUM('0', '1') NOT NULL DEFAULT '0',
    expire_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);