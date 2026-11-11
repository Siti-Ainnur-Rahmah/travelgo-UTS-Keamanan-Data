CREATE DATABASE IF NOT EXISTS db_travel CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE db_travel;

CREATE TABLE IF NOT EXISTS routes (
  id INT AUTO_INCREMENT PRIMARY KEY,
  origin VARCHAR(80) NOT NULL,
  destination VARCHAR(80) NOT NULL,
  depart_time VARCHAR(5) NOT NULL,
  price INT NOT NULL,
  vehicle VARCHAR(80) NOT NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS bookings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  code VARCHAR(20) NOT NULL UNIQUE,
  route_id INT NOT NULL,
  travel_date DATE NOT NULL,
  seats TINYINT NOT NULL DEFAULT 1,
  status ENUM('pending','confirmed','cancelled') NOT NULL DEFAULT 'pending',
  enc_data MEDIUMTEXT NOT NULL,   
  enc_key TEXT NOT NULL,          
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (route_id) REFERENCES routes(id) ON DELETE CASCADE
) ENGINE=InnoDB;

INSERT INTO routes (origin, destination, depart_time, price, vehicle) VALUES
('Jakarta', 'Bandung', '07:00', 120000, 'Hiace Premio'),
('Bandung', 'Surabaya', '19:30', 350000, 'Bus Executive'),
('Sukabumi', 'Jakarta', '06:00', 85000, 'Elf Long'),
('Jakarta', 'Semarang', '21:00', 210000, 'Bus Sleeper'),
('Sukabumi', 'Bandung', '08:00', 75000, 'Toyota Hiace'),
('Bandung', 'Yogyakarta', '18:00', 250000, 'Bus Executive'),
('Jakarta', 'Malang', '15:00', 380000, 'Bus Sleeper'),
('Depok', 'Surabaya', '14:30', 400000, 'Bus Executive VIP'),
('Sukabumi', 'Bogor', '09:00', 50000, 'Avanza / Xenia'),
('Bandung', 'Bali (Denpasar)', '10:00', 650000, 'Bus Double Decker');