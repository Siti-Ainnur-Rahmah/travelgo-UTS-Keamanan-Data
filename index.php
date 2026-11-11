<?php
require 'config.php';

$page = $_GET['page'] ?? 'home';
if(!in_array($page, ['home','login','admin','logout'])) $page = 'home';

if($page === 'logout'){
    session_destroy();
    header('Location: index.php?page=login'); exit;
}

// Login Admin (Memeriksa inputan kunci)
if($page === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST'){
    $key_input = '';
    if (!empty($_FILES['file_key']['tmp_name']) && $_FILES['file_key']['error'] === UPLOAD_ERR_OK) {
        $key_input = file_get_contents($_FILES['file_key']['tmp_name']);
    } else {
        $key_input = $_POST['secret_key'] ?? '';
    }

    // Bersihkan semua spasi dan enter dari inputan maupun kunci sistem
    $clean_input = preg_replace('/\s+/', '', $key_input);
    $clean_system = preg_replace('/\s+/', '', AES_SECRET_KEY);

    // Validasi kecocokan
    $valid = ($clean_input === $clean_system && $clean_system !== '') ? AES_SECRET_KEY : '';
    
    session_regenerate_id(true);
    $_SESSION['login'] = true;
    $_SESSION['aes_key'] = $valid;
    header('Location: index.php?page=admin'); exit;
}

if($page === 'admin'){
    if(empty($_SESSION['login'])){ header('Location: index.php?page=login'); exit; }
    $aes_key = $_SESSION['aes_key'] ?? '';
    $locked = ($aes_key === '');
    $pdo = db();

    if(isset($_POST['status'], $_POST['id'])){
        $pdo->prepare('UPDATE bookings SET status=? WHERE id=?')->execute([$_POST['status'], $_POST['id']]);
    }
    $rows = $pdo->query('SELECT b.*, r.origin, r.destination, r.vehicle, r.price FROM bookings b JOIN routes r ON r.id=b.route_id ORDER BY b.id DESC')->fetchAll();
}

$msg = ''; $cek = null; $cekMsg = '';
if($page === 'home'){
    if($_SERVER['REQUEST_METHOD'] === 'POST'){
        try{
            $r = db()->prepare('SELECT * FROM routes WHERE id=?');
            $r->execute([$_POST['route_id']]);
            $route = $r->fetch();
            if(!$route) throw new Exception('Rute tidak valid.');
            if(!preg_match('/^\d{16}$/', $_POST['ktp'])) throw new Exception('Nomor KTP harus 16 digit.');

            $seats = max(1, (int)$_POST['seats']);
            $code = 'TRV-'.rand(1000, 9999);
            
            $enc_data = aes_encrypt([
                'code' => $code,
                'nama' => $_POST['nama'],
                'ktp' => $_POST['ktp'],
                'hp' => $_POST['hp'],
                'seats' => $seats
            ]);

            db()->prepare('INSERT INTO bookings(code, route_id, travel_date, seats, status, enc_data, enc_key) VALUES(?,?,?,?,?,?,?)')
              ->execute([hash('sha256', $code), $_POST['route_id'], $_POST['travel_date'], $seats, 'pending', $enc_data, 'AES-256-CBC']);

            $msg = '<div class="alert-box success">✨ Pemesanan Berhasil! Kode Booking Anda: <b>'.$code.'</b> (Simpan untuk cek status).</div>';
        }catch(Exception $ex){
            $msg = '<div class="alert-box error">⚠️ '.e($ex->getMessage()).'</div>';
        }
    }

    if(!empty($_GET['kode'])){
        $q = db()->prepare('SELECT b.travel_date, b.seats, b.status, r.origin, r.destination, r.vehicle, r.price 
                            FROM bookings b JOIN routes r ON r.id=b.route_id WHERE b.code=?');
        $q->execute([hash('sha256', strtoupper(trim($_GET['kode'])))]);
        $cek = $q->fetch();
        if(!$cek) $cekMsg = '<div class="alert-box error">⚠️ Kode booking tidak ditemukan.</div>';
    }
    $routes = db()->query('SELECT * FROM routes')->fetchAll();
}
?>
<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TravelGo - Secure Ticket Booking (AES-256)</title>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root {
    --primary: #4f46e5; --primary-dark: #4338ca; --primary-light: #eef2ff;
    --accent: #06b6d4; --bg-color: #f8fafc; --card-bg: #ffffff; --text-main: #0f172a; --text-muted: #64748b; --border-color: #e2e8f0;
}
* { box-sizing: border-box; transition: all 0.2s ease; }
body { margin: 0; font-family: 'Plus Jakarta Sans', sans-serif; background: var(--bg-color); color: var(--text-main); }

header { position: sticky; top: 0; z-index: 100; background: rgba(255, 255, 255, 0.85); backdrop-filter: blur(12px); border-bottom: 1px solid var(--border-color); padding: 18px 8%; display: flex; justify-content: space-between; align-items: center; }
.logo { font-size: 22px; font-weight: 800; color: #0284c7; text-decoration: none; display: flex; align-items: center; gap: 8px; }
nav a { color: var(--text-muted); margin-left: 28px; text-decoration: none; font-size: 14px; font-weight: 600; }
nav a:hover { color: #0284c7; }
.nav-btn-admin { background: #e0f2fe; color: #0284c7 !important; padding: 10px 22px; border-radius: 14px; font-weight: 700 !important; }

.hero-banner-large { max-width: 1100px; margin: 35px auto 0; padding: 60px 50px; background: linear-gradient(135deg, #4f46e5 0%, #6366f1 50%, #06b6d4 100%); border-radius: 30px; color: white; text-align: center; box-shadow: 0 20px 40px -10px rgba(79, 70, 229, 0.3); }
.hero-badge-large { display: inline-flex; align-items: center; gap: 6px; background: rgba(255, 255, 255, 0.18); backdrop-filter: blur(8px); padding: 8px 18px; border-radius: 20px; font-size: 13px; font-weight: 700; margin-bottom: 20px; border: 1px solid rgba(255,255,255,0.2); }
.hero-banner-large h1 { font-size: 42px; font-weight: 800; margin: 0 0 16px; letter-spacing: -0.5px; line-height: 1.2; }
.hero-banner-large p { font-size: 16px; opacity: 0.92; max-width: 650px; margin: 0 auto 30px; line-height: 1.6; font-weight: 500; }
.hero-features-grid { display: flex; justify-content: center; gap: 16px; flex-wrap: wrap; margin-top: 20px; }
.hero-features-grid div { background: rgba(255,255,255,0.12); padding: 12px 20px; border-radius: 14px; font-size: 14px; font-weight: 600; backdrop-filter: blur(4px); border: 1px solid rgba(255,255,255,0.15); }

.main-container { max-width: 850px; margin: 40px auto 60px; padding: 0 20px; }
.form-card-large { background: #ffffff; border: 1px solid var(--border-color); border-radius: 28px; padding: 44px; box-shadow: 0 20px 30px -10px rgba(0,0,0,0.04); }
.form-card-large h2 { font-size: 24px; font-weight: 800; margin: 0 0 28px; color: #0f172a; display: flex; align-items: center; gap: 10px; }

label { display: block; font-weight: 700; font-size: 12px; margin-bottom: 6px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.5px; }
input, select { width: 100%; padding: 14px 18px; margin-bottom: 22px; font-family: inherit; font-size: 14px; background: #f8fafc; border: 1px solid var(--border-color); border-radius: 14px; outline: none; color: #0f172a; }
input:focus, select:focus { border-color: var(--primary); background: #fff; box-shadow: 0 0 0 4px var(--primary-light); }
button { width: 100%; padding: 16px; background: var(--primary); color: white; border: 0; border-radius: 14px; font-weight: 700; font-size: 16px; cursor: pointer; box-shadow: 0 10px 20px -5px rgba(79, 70, 229, 0.4); }
button:hover { background: var(--primary-dark); transform: translateY(-2px); }

.alert-box { padding: 16px 20px; border-radius: 14px; margin-bottom: 24px; font-size: 14px; font-weight: 600; }
.alert-box.success { background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; }
.alert-box.error { background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; }

.login-body { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; background: linear-gradient(135deg, #e0e7ff 0%, #fae8ff 100%); }
.login-card { background: #ffffff; width: 100%; max-width: 520px; padding: 45px 40px; border-radius: 28px; box-shadow: 0 25px 50px -12px rgba(79, 70, 229, 0.15); text-align: center; border: 1px solid rgba(255,255,255,0.8); }
.icon-key { width: 72px; height: 72px; background: #fef08a; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 20px; font-size: 30px; box-shadow: 0 10px 20px rgba(250, 204, 21, 0.3); }
.upload-box { border: 2px dashed var(--border-color); border-radius: 14px; padding: 16px; background: #f8fafc; margin-bottom: 20px; text-align: left; }
.upload-box label { display: block; font-size: 11px; font-weight: 800; color: var(--text-muted); letter-spacing: 0.5px; margin-bottom: 8px; }
.divider { display: flex; align-items: center; text-align: center; color: var(--text-muted); font-size: 11px; font-weight: 800; letter-spacing: 0.5px; margin: 20px 0; }
.divider::before, .divider::after { content: ''; flex: 1; border-bottom: 1px solid var(--border-color); }
.divider::before { margin-right: 12px; }
.divider::after { margin-left: 12px; }

.admin-navbar { background: #ffffff; padding: 18px 6%; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e2e8f0; position: sticky; top: 0; z-index: 100; }
.admin-logo { font-size: 20px; font-weight: 800; color: #0284c7; text-decoration: none; }
.badge-key-active { background: #dcfce7; color: #166534; padding: 6px 14px; border-radius: 20px; font-size: 13px; font-weight: 700; display: inline-flex; align-items: center; gap: 6px; }
.badge-key-locked { background: #fee2e2; color: #b91c1c; padding: 6px 14px; border-radius: 20px; font-size: 13px; font-weight: 700; display: inline-flex; align-items: center; gap: 6px; }
.btn-logout { color: #ef4444; font-weight: 700; text-decoration: none; font-size: 14px; margin-left: 15px; }
.admin-container { max-width: 1150px; margin: 30px auto; padding: 0 20px; }
.dash-title { font-size: 26px; font-weight: 800; margin: 0 0 6px; color: #0f172a; }
.dash-subtitle { color: #64748b; font-size: 14px; margin: 0 0 28px; }
.stat-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; }
.stat-card { background: #ffffff; border-radius: 18px; padding: 24px; display: flex; align-items: center; gap: 20px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.03); border: 1px solid #f1f5f9; }
.stat-icon-blue { width: 56px; height: 56px; background: #e0f2fe; color: #0284c7; border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 24px; }
.stat-icon-green { width: 56px; height: 56px; background: #dcfce7; color: #166534; border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 24px; }
.stat-icon-red { width: 56px; height: 56px; background: #fee2e2; color: #b91c1c; border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 24px; }
.stat-label { font-size: 13px; color: #64748b; font-weight: 600; margin-bottom: 4px; }
.stat-val { font-size: 24px; font-weight: 800; color: #0f172a; margin: 0; }
.table-card { background: #ffffff; border-radius: 20px; padding: 28px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.03); border: 1px solid #f1f5f9; }
.table-header-title { font-size: 18px; font-weight: 800; color: #0f172a; margin-bottom: 24px; display: flex; align-items: center; gap: 10px; }
.custom-table { width: 100%; border-collapse: collapse; text-align: left; }
.custom-table th { padding: 14px 16px; color: #64748b; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #f1f5f9; }
.custom-table td { padding: 20px 16px; border-bottom: 1px solid #f8fafc; font-size: 14px; vertical-align: middle; }
.code-badge { color: #0284c7; font-weight: 800; font-size: 14px; }
.route-text { font-weight: 800; color: #0f172a; font-size: 14px; margin-bottom: 4px; }
.date-text { color: #94a3b8; font-size: 12px; font-weight: 600; display: flex; align-items: center; gap: 4px; }
.passenger-name { font-weight: 700; color: #15803d; font-size: 14px; display: flex; align-items: center; gap: 6px; }
.passenger-ktp { color: #64748b; font-size: 12px; margin-top: 4px; font-weight: 500; }
.passenger-phone { color: #0f172a; font-weight: 700; font-size: 14px; display: flex; align-items: center; gap: 6px; }
.cipher-box { background: #fafafa; border: 1px dashed #cbd5e1; border-radius: 8px; padding: 8px 12px; font-family: Consolas, monospace; font-size: 11px; color: #334155; word-break: break-all; display: inline-flex; align-items: center; gap: 8px; max-width: 380px; }
</style>
</head>
<body>

<?php if($page === 'login'): ?>
<!-- HALAMAN LOGIN ADMIN -->
<div class="login-body">
  <div class="login-card">
    <div class="icon-key">🔑</div>
    <h2>Otentikasi Kunci AES-256</h2>
    <p style="color: var(--text-muted); font-size: 14px; margin-bottom: 24px;">Unggah file kunci (.pem/.txt) atau paste Kunci AES di bawah ini untuk dekripsi data:</p>

    <form method="post" enctype="multipart/form-data">
      <div class="upload-box">
        <label>📁 UPLOAD FILE KEY (.PEM / .TXT)</label>
        <input type="file" name="file_key" accept=".pem,.txt,.key" style="width: 100%; border: 0; background: transparent; padding: 0; cursor: pointer;">
      </div>

      <div class="divider">ATAU KETIK / PASTE KUNCI</div>

      <div style="text-align: left; margin-bottom: 22px;">
        <label><code>&lt;/&gt;</code> KUNCI RAHASIA AES-256</label>
        <!-- Textarea besar supaya kunci 3 baris bisa terlihat dan dipaste dengan rapi -->
        <textarea name="secret_key" rows="4" placeholder="Paste kunci -----BEGIN AES SECRET KEY----- di sini..." style="width: 100%; padding: 14px; border: 1px solid var(--border-color); border-radius: 14px; font-family: monospace; font-size: 12px; resize: vertical; margin-bottom:0;"></textarea>
      </div>

      <button>Validasi & Buka Dashboard 🔒</button>
    </form>
    
    <div style="margin-top: 20px;">
      <a href="index.php?page=home" style="color: var(--text-muted); font-size: 14px; font-weight: 600; text-decoration: none;">← Kembali ke Beranda</a>
    </div>
  </div>
</div>

<?php elseif($page === 'admin'): ?>
<!-- DASHBOARD ADMIN -->
<div class="admin-navbar">
  <a href="#" class="admin-logo">TravelGo Admin</a>
  <div style="display: flex; align-items: center;">
    <?php if(!$locked): ?>
      <span class="badge-key-active">🔑 Kunci AES Valid</span>
    <?php else: ?>
      <span class="badge-key-locked">🔒 Tanpa Kunci</span>
    <?php endif; ?>
    <a href="index.php?page=logout" class="btn-logout">[→ Keluar</a>
  </div>
</div>

<div class="admin-container">
  <h1 class="dash-title">Dashboard Manifes Penumpang</h1>
  <p class="dash-subtitle">Sistem otomatis mendekripsi data sensitif (Nama, KTP, HP) menggunakan Kunci AES-256.</p>

  <div class="stat-grid">
    <div class="stat-card">
      <div class="stat-icon-blue">🎫</div>
      <div>
        <div class="stat-label">Total Pemesanan</div>
        <h3 class="stat-val"><?= count($rows) ?> Tiket</h3>
      </div>
    </div>
    <div class="stat-card">
      <?php if(!$locked): ?>
        <div class="stat-icon-green">🔓</div>
        <div>
          <div class="stat-label">Status Data</div>
          <h3 class="stat-val" style="color: #15803d;">Berhasil Didekripsi</h3>
        </div>
      <?php else: ?>
        <div class="stat-icon-red">🔒</div>
        <div>
          <div class="stat-label">Status Data</div>
          <h3 class="stat-val" style="color: #b91c1c;">Terkunci (Ciphertext)</h3>
        </div>
      <?php endif; ?>
    </div>
  </div>

  <div class="table-card">
    <div class="table-header-title">
      📋 Daftar Penumpang <?= !$locked ? '(Data Asli)' : '(Terenkripsi AES-256)' ?>
    </div>
    
    <div style="overflow-x: auto;">
      <table class="custom-table">
        <thead>
          <tr>
            <th>KODE</th>
            <th>RUTE & TANGGAL</th>
            <th>DATA PRIBADI (DECRYPTED)</th>
            <th>KONTAK (DECRYPTED)</th>
            <th>BENTUK ASLI DI DB (CIPHERTEXT)</th>
          </tr>
        </thead>
        <tbody>
          <?php foreach($rows as $r):
            $dec = $locked ? null : aes_decrypt($r['enc_data'], $aes_key);
          ?>
          <tr>
            <td><span class="code-badge">TRV-<?= e($r['id'] * 1234 + 1000) ?></span></td>
            <td>
              <div class="route-text"><?= e($r['origin']) ?> - <?= e($r['destination']) ?></div>
              <div class="date-text">📅 <?= e($r['travel_date']) ?></div>
            </td>
            <td>
              <?php if($dec): ?>
                <div class="passenger-name">👤 <?= e($dec['nama']) ?></div>
                <div class="passenger-ktp">KTP: <?= e($dec['ktp']) ?></div>
              <?php else: ?>
                <span style="color: #ef4444; font-size: 13px; font-weight: 600;">🔒 Terkunci</span>
              <?php endif; ?>
            </td>
            <td>
              <?php if($dec): ?>
                <div class="passenger-phone">💬 <?= e($dec['hp']) ?></div>
              <?php else: ?>
                <span style="color: #ef4444; font-size: 13px; font-weight: 600;">🔒 Terkunci</span>
              <?php endif; ?>
            </td>
            <td>
              <div class="cipher-box">
                <span style="color: #ef4444;">🔒</span> <?= e(substr($r['enc_data'], 0, 42)) ?>==
              </div>
            </td>
          </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  </div>
</div>

<?php else: ?>
<!-- LANDING PAGE -->
<header>
  <a href="#" class="logo">🚐 TravelGo</a>
  <nav>
    <a href="#pesan">Pesan Tiket</a>
    <a href="#cek">Cek Status</a>
    <a href="index.php?page=login" class="nav-btn-admin">Admin Login</a>
  </nav>
</header>

<div class="hero-banner-large">
  <div class="hero-badge-large">🛡️ Keamanan Data Berbasis AES-256-CBC</div>
  <h1>TravelGo – Perjalanan Aman & Nyaman</h1>
  <p>Pesan tiket travel antar kota dengan jaminan perlindungan enkripsi tingkat tinggi untuk menjaga privasi data pribadi Anda.</p>
  
  <div class="hero-features-grid">
    <div>🔒 Data KTP & HP Terenkripsi Otomatis</div>
    <div>🚌 Armada Hiace & Bus Executive Nyaman</div>
    <div>🎫 Konfirmasi Instan dengan Kode Booking</div>
  </div>
</div>

<div class="main-container">
  <div class="form-card-large" id="pesan">
    <h2>📝 Form Pemesanan Tiket Travel</h2>
    <?=$msg?>
    <form method="post">
      <label>Pilih Rute Perjalanan:</label>
      <select name="route_id" required>
        <?php foreach($routes as $rt): ?>
          <option value="<?=$rt['id']?>"><?=e($rt['origin'])?> → <?=e($rt['destination'])?> (<?=e($rt['vehicle'])?> - <?=rp($rt['price'])?>)</option>
        <?php endforeach; ?>
      </select>
      
      <label>Nama Lengkap (Sesuai KTP):</label>
      <input name="nama" required placeholder="Contoh: Siti Ainnur">
      
      <label>Nomor KTP (16 digit):</label>
      <input name="ktp" required maxlength="16" placeholder="3207xxxxxxxxxxxx">
      
      <label>Nomor Telepon / WhatsApp:</label>
      <input name="hp" required placeholder="08xxxxxxxxxx">
      
      <label>Jumlah Kursi:</label>
      <input type="number" name="seats" value="1" min="1" max="5" required>
      
      <label>Tanggal Keberangkatan:</label>
      <input type="date" name="travel_date" required>
      
      <button>Konfirmasi & Pesan Tiket</button>
    </form>
  </div>

  <div class="form-card-large" id="cek" style="margin-top: 40px;">
    <h2>🔍 Cek Status Pesanan Tiket</h2>
    <form method="get" action="#cek">
      <label>Masukkan Kode Booking:</label>
      <input name="kode" placeholder="Contoh: TRV-A1B2C3" value="<?=e($_GET['kode'] ?? '')?>" required>
      <button style="background: var(--text-main);">Cek Status Pesanan</button>
    </form>
    <?=$cekMsg?>
    <?php if($cek): ?>
      <div style="margin-top: 20px; background: #f8fafc; border: 1px solid var(--primary); border-radius: 16px; padding: 20px;">
        <span style="background: #dcfce7; color: #15803d; padding: 4px 12px; border-radius: 20px; font-weight: 700; font-size: 12px;"><?=e($cek['status'])?></span>
        <p style="margin: 14px 0 6px; font-weight: 700;">Rute: <?=e($cek['origin'])?> → <?=e($cek['destination'])?> (<?=e($cek['vehicle'])?>)</p>
        <p style="margin: 0; color: #64748b; font-size: 13px;">Tanggal: <?=e($cek['travel_date'])?> | Total: <?=rp($cek['price'] * $cek['seats'])?></p>
      </div>
    <?php endif; ?>
  </div>
</div>
<?php endif; ?>

</body>
</html>