const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const path = require('path');
const bodyParser = require('body-parser');
const session = require('express-session');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');

const config = {
  host: 'localhost',
  user: 'root',
  password: 'P@ssw0rd123!',
  database: 'login',
  port : 3306
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname); 
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'video/mp4'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Format file tidak diizinkan. Hanya file jpeg, jpg, png, dan mp4 yang diperbolehkan.'), false);
  }
};

const upload = multer({ storage: storage, fileFilter: fileFilter });

const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.use(session({
  secret: 'secretkey',
  resave: false,
  saveUninitialized: true,
}));
// Agar folder downloads bisa diakses secara publik
app.use('/downloads', express.static(path.join(__dirname, 'downloads')));

function embedImageToImage(mainImagePath, embeddedImagePath, outputImagePath) {
  try {
      const mainImageData = fs.readFileSync(mainImagePath); // Membaca gambar utama
      const embeddedImageData = fs.readFileSync(embeddedImagePath); // Membaca gambar yang akan disisipkan

      // Tambahkan header khusus sebelum data gambar tersembunyi untuk penanda
      const header = Buffer.from('EMBEDDED_IMAGE_START');
      const combinedData = Buffer.concat([mainImageData, header, embeddedImageData]);

      // Simpan gambar hasil dengan data tersembunyi
      fs.writeFileSync(outputImagePath, combinedData);
      console.log('Gambar berhasil disisipkan ke:', outputImagePath);

      // Debugging: Cek ukuran file untuk memastikan penyisipan berhasil
      console.log('Ukuran gambar utama:', mainImageData.length);
      console.log('Ukuran gambar disisipkan:', embeddedImageData.length);
      console.log('Ukuran gambar hasil:', combinedData.length);
  } catch (error) {
      console.error('Error saat menyisipkan gambar:', error.message);
  }
}

// Fungsi Enkripsi dan Dekripsi (Caesar, Vigenere, AES)
function caesarEncrypt(text, shift) {
  return text.split('').map(char => {
    let code = char.charCodeAt(0);
    if (code >= 65 && code <= 90) {
      return String.fromCharCode(((code - 65 + shift) % 26) + 65);
    } else if (code >= 97 && code <= 122) {
      return String.fromCharCode(((code - 97 + shift) % 26) + 97);
    }
    return char;
  }).join('');
}

function caesarDecrypt(text, shift) {
  return text.split('').map(char => {
    let code = char.charCodeAt(0);
    if (code >= 65 && code <= 90) {
      return String.fromCharCode(((code - 65 - shift + 26) % 26) + 65);
    } else if (code >= 97 && code <= 122) {
      return String.fromCharCode(((code - 97 - shift + 26) % 26) + 97);
    }
    return char;
  }).join('');
}

function vigenereEncrypt(text, key) {
  let result = '';
  for (let i = 0, j = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 65 && c <= 90) {
      result += String.fromCharCode(((c - 65 + key.charCodeAt(j % key.length) - 65) % 26) + 65);
      j++;
    } else if (c >= 97 && c <= 122) {
      result += String.fromCharCode(((c - 97 + key.charCodeAt(j % key.length) - 97) % 26) + 97);
      j++;
    } else {
      result += text.charAt(i);
    }
  }
  return result;
}

function vigenereDecrypt(text, key) {
  let result = '';
  for (let i = 0, j = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 65 && c <= 90) {
      result += String.fromCharCode(((c - 65 - (key.charCodeAt(j % key.length) - 65) + 26) % 26) + 65);
      j++;
    } else if (c >= 97 && c <= 122) {
      result += String.fromCharCode(((c - 97 - (key.charCodeAt(j % key.length) - 97) + 26) % 26) + 97);
      j++;
    } else {
      result += text.charAt(i);
    }
  }
  return result;
}

function aesEncrypt(text, key, keySize) {
  let requiredLength;
  switch (keySize) {
    case '128':
      requiredLength = 16;
      break;
    case '192':
      requiredLength = 24;
      break;
    case '256':
      requiredLength = 32;
      break;
    default:
      throw new Error('Ukuran kunci tidak valid');
  }

  if (key.length !== requiredLength) {
    throw new Error(`Panjang kunci harus ${requiredLength} karakter untuk AES-${keySize}`);
  }

  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(`aes-${keySize}-cbc`, Buffer.from(key), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function aesDecrypt(text, key, keySize) {
  let requiredLength;
  switch (keySize) {
    case '128':
      requiredLength = 16;
      break;
    case '192':
      requiredLength = 24;
      break;
    case '256':
      requiredLength = 32;
      break;
    default:
      throw new Error('Ukuran kunci tidak valid');
  }

  if (key.length !== requiredLength) {
    throw new Error(`Panjang kunci harus ${requiredLength} karakter untuk AES-${keySize}`);
  }

  const parts = text.split(':');
  const iv = Buffer.from(parts.shift(), 'hex');
  const encryptedText = Buffer.from(parts.join(':'), 'hex');
  const decipher = crypto.createDecipheriv(`aes-${keySize}-cbc`, Buffer.from(key), iv);
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Fungsi untuk menyisipkan pesan ke dalam file (gambar/video)
function extractImageFromImage(filePath, outputImagePath) {
  try {
      const data = fs.readFileSync(filePath); // Membaca file gambar utama

      // Cari header untuk menandai awal data gambar tersembunyi
      const header = Buffer.from('EMBEDDED_IMAGE_START');
      const headerIndex = data.indexOf(header);

      // Jika header tidak ditemukan
      if (headerIndex === -1) {
          throw new Error('Tidak ditemukan gambar tersembunyi dalam file.');
      }

      // Pisahkan data gambar tersembunyi
      const embeddedImageData = data.slice(headerIndex + header.length);

      // Menyimpan data gambar tersembunyi sebagai file baru
      fs.writeFileSync(outputImagePath, embeddedImageData);

      console.log('Gambar berhasil diekstrak ke:', outputImagePath);
      return 'Gambar berhasil diekstrak!';
  } catch (error) {
      console.error('Error saat ekstraksi gambar:', error.message);
      return 'Error saat ekstraksi gambar.';
  }
}


function embedMessageToFile(filePath, message, outputFilePath) {
  const data = fs.readFileSync(filePath);
  const combinedData = Buffer.concat([data, Buffer.from('\n' + message)]);
  fs.writeFileSync(outputFilePath, combinedData);
}

function extractMessageFromFile(filePath) {
  const data = fs.readFileSync(filePath, 'utf8');
  const splitData = data.split('\n');
  return splitData[splitData.length - 1];
}

// Route untuk halaman login
app.get('/', (req, res) => {
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  console.log('Username:', username);  // Log untuk melihat apakah username diterima
  console.log('Password:', password);  // Log untuk melihat apakah password diterima
  
  try {
    const connection = await mysql.createConnection(config);
    const [rows] = await connection.execute('SELECT * FROM admin WHERE username = ?', [username]);
    console.log('Rows:', rows);  // Log untuk melihat hasil query

    if (rows.length > 0) {
      const validPassword = await bcrypt.compare(password, rows[0].password);
      console.log('Password match:', validPassword);  // Log hasil bcrypt.compare
      
      if (validPassword) {
        req.session.loggedIn = true;
        req.session.username = username;
        res.json({ success: true });
      } else {
        res.json({ success: false, message: 'Password salah!' });
      }
    } else {
      res.json({ success: false, message: 'Username tidak ditemukan!' });
    }

    await connection.end();
  } catch (err) {
    console.error('Error saat koneksi ke database:', err);
    res.json({ success: false, message: 'Error saat koneksi ke database.' });
  }
});


// Route untuk halaman register
app.get('/register', (req, res) => {
  res.render('register');
});
// Route untuk halaman register
app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res.json({ success: false, message: 'Semua field harus diisi!' });
  }

  try {
    const connection = await mysql.createConnection(config);
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = `INSERT INTO admin (username, password, email) VALUES (?, ?, ?)`;

    await connection.execute(query, [username, hashedPassword, email]);
    console.log('Admin baru ditambahkan');

    res.json({ success: true });

    await connection.end();
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      console.error('Username sudah terdaftar:', err);
      res.json({ success: false, message: 'Username sudah terdaftar. Silakan gunakan username lain.' });
    } else {
      console.error('Error saat menyimpan admin ke database:', err);
      res.json({ success: false, message: 'Error saat menyimpan admin ke database.' });
    }
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.redirect('/dashboard');
    }
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

app.get('/dashboard', (req, res) => {
  res.render('dashboard');
});

app.get('/upload-photo', (req, res) => {
  res.render('upload-photo', { downloadLink: undefined, decryptedMessage: undefined });
});

app.get('/upload-video', (req, res) => {
  res.render('upload-video');
});

app.post('/upload-photo', upload.fields([{ name: 'photo', maxCount: 1 }, { name: 'secret-image', maxCount: 1 }]), (req, res) => {
  const { message, encryption, key, 'key-size': keySize, 'steganography-type': embedOption } = req.body;
  const photo = req.files['photo'] ? req.files['photo'][0] : null;
  const embeddedImage = req.files['secret-image'] ? req.files['secret-image'][0] : null;

  if (!photo) {
      return res.render('upload-photo', { downloadLink: undefined, errorMessage: 'File foto tidak ditemukan!' });
  }

  try {
      const outputFilePath = path.join(__dirname, 'downloads', `gambar_dengan_pesan_rahasia${path.extname(photo.originalname)}`);

      if (embedOption === 'image' && embeddedImage) {
          // Menyisipkan gambar ke dalam gambar
          embedImageToImage(photo.path, embeddedImage.path, outputFilePath);
      } else if (embedOption === 'message') {
          // Enkripsi pesan teks dan sisipkan ke dalam gambar
          let encryptedMessage;
          switch (encryption) {
              case 'caesar':
                  encryptedMessage = caesarEncrypt(message, parseInt(key));
                  break;
              case 'vigenere':
                  encryptedMessage = vigenereEncrypt(message, key);
                  break;
              case 'aes':
                  encryptedMessage = aesEncrypt(message, key, keySize);
                  break;
              default:
                  throw new Error('Metode enkripsi tidak valid!');
          }
          embedMessageToFile(photo.path, encryptedMessage, outputFilePath);
      }

      res.render('upload-photo', { downloadLink: `/downloads/${path.basename(outputFilePath)}`, errorMessage: undefined });
  } catch (error) {
      res.render('upload-photo', { downloadLink: undefined, errorMessage: `Error saat proses enkripsi: ${error.message}` });
  }
});


app.post('/upload-video', upload.single('video'), (req, res) => {
  const { message, encryption, key, 'key-size': keySize } = req.body;
  const video = req.file;

  if (!video) {
    return res.render('upload-video', { downloadLink: undefined, decryptedMessage: 'File video tidak ditemukan!' });
  }

  let encryptedMessage;

  switch (encryption) {
    case 'caesar':
      if (isNaN(key)) {
        return res.render('upload-video', { downloadLink: undefined, decryptedMessage: 'Kunci untuk Caesar Cipher harus berupa angka!' });
      }
      encryptedMessage = caesarEncrypt(message, parseInt(key));
      break;
    case 'vigenere':
      if (!/^[A-Za-z]+$/.test(key)) {
        return res.render('upload-video', { downloadLink: undefined, decryptedMessage: 'Kunci untuk Vigenère Cipher harus berupa huruf!' });
      }
      encryptedMessage = vigenereEncrypt(message, key);
      break;
    case 'aes':
      try {
        encryptedMessage = aesEncrypt(message, key, keySize);
      } catch (err) {
        return res.render('upload-video', { downloadLink: undefined, decryptedMessage: err.message });
      }
      break;
    default:
      return res.render('upload-video', { downloadLink: undefined, decryptedMessage: 'Metode enkripsi tidak valid!' });
  }

  const fileExtension = path.extname(video.originalname);
  const outputFileName = `video_dengan_pesan_rahasia${fileExtension}`;
  const outputFilePath = path.join(__dirname, 'downloads', outputFileName);
  embedMessageToFile(video.path, encryptedMessage, outputFilePath);

  res.render('upload-video', { downloadLink: `/downloads/${outputFileName}`, decryptedMessage: undefined });
});

// Route untuk download file yang sudah disisipkan pesan
app.get('/downloads/:filename', (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(__dirname, 'downloads', filename);

  fs.access(filePath, fs.constants.F_OK, (err) => {
    if (err) {
      console.error("File tidak ditemukan:", err);
      return res.status(404).send('File tidak ditemukan');
    }

    res.download(filePath, filename, (downloadErr) => {
      if (downloadErr) {
        console.error("Error saat mendownload file:", downloadErr);
        res.status(500).send('Error saat mendownload file.');
      }
    });
  });
});


app.get('/extract-video', (req, res) => {
  res.send(`
    <h2>Upload Video untuk Melihat Data Terenkripsi</h2>
    <form action="/extract-message-video" method="POST" enctype="multipart/form-data">
      <label for="video">Pilih Video:</label>
      <input type="file" id="video" name="video" accept=".mp4" required>
      <label for="key">Masukkan Kunci:</label>
      <input type="text" id="key" name="key" required>
      <label for="encryption">Metode Enkripsi:</label>
      <select id="encryption" name="encryption" required>
        <option value="caesar">Caesar Cipher</option>
        <option value="vigenere">Vigenère Cipher</option>
        <option value="aes">AES Encryption</option>
      </select>
      <button type="submit">Lihat Pesan Terenkripsi</button>
    </form>
  `);
});

// Route untuk mengekstrak pesan dari video
app.post('/extract-message-video', upload.single('video'), (req, res) => {
  const { encryption, key, 'key-size': keySize } = req.body;
  const video = req.file;

  if (!video) {
    return res.render('upload-video', { downloadLink: undefined, decryptedMessage: 'File video tidak ditemukan!' });
  }

  const extractedMessage = extractMessageFromFile(video.path);

  let decryptedMessage;
  try {
    switch (encryption) {
      case 'caesar':
        decryptedMessage = caesarDecrypt(extractedMessage, parseInt(key));
        break;
      case 'vigenere':
        decryptedMessage = vigenereDecrypt(extractedMessage, key);
        break;
      case 'aes':
        decryptedMessage = aesDecrypt(extractedMessage, key, keySize);
        break;
      default:
        decryptedMessage = 'Metode dekripsi tidak valid!';
    }
  } catch (err) {
    decryptedMessage = 'Error saat dekripsi: ' + err.message;
  }

  res.render('upload-video', { decryptedMessage, downloadLink: undefined });
});

// Route untuk mengekstrak gambar yang disisipkan dari gambar utama
app.post('/extract-message', upload.single('photo'), (req, res) => {
  const { 'extract-type': extractType, encryption, key, 'key-size': keySize } = req.body;
  const photo = req.file;

  if (!photo) {
    return res.render('upload-photo', { 
      downloadLink: undefined, 
      extractedMessage: 'File foto tidak ditemukan!', 
      extractedImageLink: undefined 
    });
  }

  try {
    if (extractType === 'image') {
      // Ekstraksi gambar tersembunyi
      const outputImagePath = path.join(__dirname, 'downloads', `extracted_image_${Date.now()}.png`);
      const message = extractImageFromImage(photo.path, outputImagePath);

      // Kirimkan link download untuk gambar yang berhasil diekstrak
      res.render('upload-photo', { 
        downloadLink: undefined,
        extractedMessage: undefined,
        extractedImageLink: `/downloads/${path.basename(outputImagePath)}` // Link download untuk gambar tersembunyi
      });

    } else if (extractType === 'message') {
      // Ekstraksi pesan tersembunyi
      const extractedMessage = extractMessageFromFile(photo.path);

      let decryptedMessage;
      try {
        switch (encryption) {
          case 'caesar':
            decryptedMessage = caesarDecrypt(extractedMessage, parseInt(key));
            break;
          case 'vigenere':
            decryptedMessage = vigenereDecrypt(extractedMessage, key);
            break;
          case 'aes':
            decryptedMessage = aesDecrypt(extractedMessage, key, keySize);
            break;
          default:
            decryptedMessage = 'Metode dekripsi tidak valid!';
        }
      } catch (err) {
        decryptedMessage = 'Error saat dekripsi: ' + err.message;
      }

      // Kirimkan hasil ekstraksi pesan
      res.render('upload-photo', { 
        downloadLink: undefined,
        extractedMessage: decryptedMessage,
        extractedImageLink: undefined
      });
    }
  } catch (err) {
    res.render('upload-photo', { 
      downloadLink: undefined, 
      extractedMessage: 'Error saat ekstraksi: ' + err.message, 
      extractedImageLink: undefined 
    });
  }
});

// Route untuk halaman enkripsi dan dekripsi Caesar Cipher
app.get('/encrypt-caesar', (req, res) => {
  res.render('encrypt-caesar', { encryptedText: undefined, decryptedText: undefined, errorMessage: undefined });
});

// Handler untuk enkripsi
app.post('/encrypt-caesar', (req, res) => {
  const { text, shift } = req.body;

  if (!text || !shift) {
    return res.render('encrypt-caesar', {
      encryptedText: undefined,
      decryptedText: undefined,
      errorMessage: 'Teks dan kunci harus diisi!'
    });
  }

  if (parseInt(shift) >= 26) {
    return res.render('encrypt-caesar', {
      encryptedText: undefined,
      decryptedText: undefined,
      errorMessage: 'Kunci pergeseran tidak boleh lebih dari atau sama dengan 26.'
    });
  }

  // Enkripsi teks menggunakan fungsi caesarEncrypt
  const encryptedText = caesarEncrypt(text, parseInt(shift));

  res.render('encrypt-caesar', { encryptedText, decryptedText: undefined, errorMessage: undefined });
});

// Handler untuk dekripsi
app.post('/decrypt-caesar', (req, res) => {
  const { text, shift } = req.body;

  if (!text || !shift) {
    return res.render('encrypt-caesar', {
      encryptedText: undefined,
      decryptedText: undefined,
      errorMessage: 'Teks terenkripsi dan kunci harus diisi!'
    });
  }

  if (parseInt(shift) >= 26) {
    return res.render('encrypt-caesar', {
      encryptedText: undefined,
      decryptedText: undefined,
      errorMessage: 'Kunci pergeseran tidak boleh lebih dari atau sama dengan 26.'
    });
  }

  // Dekripsi teks menggunakan fungsi caesarDecrypt
  const decryptedText = caesarDecrypt(text, parseInt(shift));

  res.render('encrypt-caesar', { encryptedText: undefined, decryptedText, errorMessage: undefined });
});


app.get('/encrypt-vigenere', (req, res) => {
  res.render('encrypt-vigenere', { encryptedText: undefined, decryptedText: undefined, errorMessage: undefined });
});

app.post('/encrypt-vigenere', (req, res) => {
  const { text, key, action } = req.body;

  if (!text || !key) {
    return res.render('encrypt-vigenere', {
      encryptedText: undefined,
      decryptedText: undefined,
      errorMessage: 'Teks dan kunci harus diisi!'
    });
  }

  // Pastikan kunci hanya berisi huruf
  if (!/^[A-Za-z]+$/.test(key)) {
    return res.render('encrypt-vigenere', {
      encryptedText: undefined,
      decryptedText: undefined,
      errorMessage: 'Kunci hanya boleh berisi huruf (A-Z atau a-z).'
    });
  }

  let result;
  if (action === 'encrypt') {
    result = vigenereEncrypt(text, key);
    res.render('encrypt-vigenere', {
      encryptedText: result,
      decryptedText: undefined,
      errorMessage: undefined
    });
  } else if (action === 'decrypt') {
    result = vigenereDecrypt(text, key);
    res.render('encrypt-vigenere', {
      encryptedText: undefined,
      decryptedText: result,
      errorMessage: undefined
    });
  }
});

app.get('/encrypt-aes', (req, res) => {
  res.render('encrypt-aes', { encryptedText: undefined, decryptedText: undefined, errorMessage: undefined });
});

app.post('/encrypt-aes', (req, res) => {
  const { text, key, keySize, action } = req.body;

  if (!text || !key || !keySize) {
    return res.render('encrypt-aes', {
      encryptedText: undefined,
      decryptedText: undefined,
      errorMessage: 'Teks, kunci, dan ukuran kunci harus diisi!'
    });
  }

  try {
    if (action === 'encrypt') {
      const encryptedText = aesEncrypt(text, key, keySize);
      res.render('encrypt-aes', {
        encryptedText,
        decryptedText: undefined,
        errorMessage: undefined
      });
    } else if (action === 'decrypt') {
      const decryptedText = aesDecrypt(text, key, keySize);
      res.render('encrypt-aes', {
        encryptedText: undefined,
        decryptedText,
        errorMessage: undefined
      });
    }
  } catch (err) {
    res.render('encrypt-aes', {
      encryptedText: undefined,
      decryptedText: undefined,
      errorMessage: err.message
    });
  }
});

// Route untuk halaman RSA
app.get('/encrypt-rsa', (req, res) => {
  res.render('encrypt-rsa', { encryptedText: undefined, decryptedText: undefined, errorMessage: undefined });
});

// Fungsi Modular Exponentiation
function modPow(base, exp, mod) {
  let result = 1;
  base = base % mod;
  while (exp > 0) {
    if (exp % 2 === 1) result = (result * base) % mod;
    exp = exp >> 1;
    base = (base * base) % mod;
  }
  return result;
}

// Fungsi untuk Generate Key RSA
function generateKeys() {
  const primes = [3, 5, 7, 11, 13, 17, 19, 23];
  const p = primes[Math.floor(Math.random() * primes.length)];
  const q = primes[Math.floor(Math.random() * primes.length)];
  const n = p * q;
  const m = (p - 1) * (q - 1);

  let e = 2;
  while (e < m && gcd(e, m) !== 1) {
    e++;
  }

  let d = 1;
  while ((e * d) % m !== 1) {
    d++;
  }

  return { p, q, n, m, e, d };
}

// Fungsi GCD
function gcd(a, b) {
  while (b !== 0) {
    let temp = b;
    b = a % b;
    a = temp;
  }
  return a;
}

// Route untuk enkripsi RSA
app.post('/encrypt-rsa', (req, res) => {
  const { text, e, n } = req.body;
  if (!text || !e || !n) {
    return res.render('encrypt-rsa', {
      encryptedText: undefined,
      decryptedText: undefined,
      errorMessage: 'Teks, e, dan n harus diisi untuk enkripsi!'
    });
  }

  const encryptedText = text.split('').map(char => modPow(char.charCodeAt(0), parseInt(e), parseInt(n))).join(', ');
  res.render('encrypt-rsa', { encryptedText, decryptedText: undefined, errorMessage: undefined });
});

// Route untuk dekripsi RSA
app.post('/decrypt-rsa', (req, res) => {
  const { encryptedText, d, n } = req.body;
  if (!encryptedText || !d || !n) {
    return res.render('encrypt-rsa', {
      encryptedText: undefined,
      decryptedText: undefined,
      errorMessage: 'Teks terenkripsi, d, dan n harus diisi untuk dekripsi!'
    });
  }

  const decryptedText = String.fromCharCode(...encryptedText.split(', ').map(num => modPow(parseInt(num), parseInt(d), parseInt(n))));
  res.render('encrypt-rsa', { encryptedText: undefined, decryptedText, errorMessage: undefined });
});


app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});