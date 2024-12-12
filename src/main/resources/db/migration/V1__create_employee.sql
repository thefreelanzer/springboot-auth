CREATE TABLE employee (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,      -- Unique identifier for each employee
    name VARCHAR(100) NOT NULL,                -- Employee's full name
    emp_code VARCHAR(50) NOT NULL UNIQUE,      -- Employee code (unique identifier)
    designation VARCHAR(100),                  -- Job title or designation
    email VARCHAR(255) NOT NULL UNIQUE,        -- Employee's email (unique)
    phone VARCHAR(15),                         -- Employee's phone number
    hire_date DATE,                            -- Date of hiring
    salary DECIMAL(15, 2),                     -- Employee's salary
    department VARCHAR(100),                   -- Department of the employee
    status VARCHAR(20) DEFAULT 'Active'       -- Status of the employee (e.g., Active, Inactive)
);