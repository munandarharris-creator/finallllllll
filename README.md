# BRI Unit Performance

## Menjalankan aplikasi

1. Instal Node.js 20 atau lebih baru.
2. Buat database dan token Turso:

   ```powershell
   turso auth login
   turso db create bri-unit-performance
   turso db show bri-unit-performance --url
   turso db tokens create bri-unit-performance
   ```

3. Salin `.env.example` menjadi `.env`, lalu isi URL, token, serta `ADMIN_USERNAME` dan `ADMIN_PASSWORD` yang kuat. Kredensial ini hanya berada di server; tidak pernah dikirimkan dalam source frontend.
4. Jalankan:

   ```powershell
   npm install
   npm start
   ```

5. Buka `http://localhost:3000`.

Tabel `app_state` dan `users` dibuat otomatis oleh backend. Password pengguna di-hash menggunakan scrypt sebelum disimpan, dan frontend hanya menerima profil pengguna serta token sesi sementara.

Jangan menyimpan `.env` ke repositori karena berisi token akses Turso.

## Deploy ke Netlify

Proyek sudah menyertakan `netlify.toml` dan Function API. Hubungkan repositori GitHub di Netlify, lalu masukkan Environment Variables berikut pada **Project configuration > Environment variables**: `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `ADMIN_NAME`, `ADMIN_KODE_REG`, dan `APP_SESSION_SECRET`. Jangan unggah file `.env` ke GitHub atau Netlify.
