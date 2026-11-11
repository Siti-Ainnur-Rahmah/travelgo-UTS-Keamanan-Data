<?php
session_start();
const DB_HOST = 'localhost';
const DB_NAME = 'db_travel';
const DB_USER = 'root';
const DB_PASS = '';

// Kunci Rahasia AES-256 dibaca dari file external (folder keys/secret.pem)
$key_file = __DIR__ . '/keys/secret.pem';
$secret_key = file_exists($key_file) ? trim(file_get_contents($key_file)) : '';
define('AES_SECRET_KEY', $secret_key);

function db(){
    static $pdo;
    return $pdo ??= new PDO('mysql:host='.DB_HOST.';dbname='.DB_NAME.';charset=utf8mb4',
        DB_USER, DB_PASS, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
}

function e($s){ return htmlspecialchars((string)$s, ENT_QUOTES); }
function rp($n){ return 'Rp '.number_format($n,0,',','.'); }

// Enkripsi Simetris AES-256-CBC
function aes_encrypt(array $data): string {
    $key = hash('sha256', AES_SECRET_KEY, true);
    $iv = random_bytes(16);
    $ciphertext = openssl_encrypt(json_encode($data), 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $ciphertext);
}

// Dekripsi Simetris AES-256-CBC
function aes_decrypt(string $enc_data, string $input_key){
    if(empty($input_key)) return null;
    
    // Bersihkan spasi/enter biar akurat 100% dan bebas error
    $clean_input = preg_replace('/\s+/', '', $input_key);
    $clean_system = preg_replace('/\s+/', '', AES_SECRET_KEY);
    
    if($clean_input !== $clean_system || $clean_system === '') return null;

    $key = hash('sha256', AES_SECRET_KEY, true);
    $raw = base64_decode($enc_data);
    if(strlen($raw) < 16) return null;
    
    $iv = substr($raw, 0, 16);
    $ciphertext = substr($raw, 16);
    
    $json = openssl_decrypt($ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    return $json === false ? null : json_decode($json, true);
}
?>