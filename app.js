require('dotenv').config();
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const fsPromises = require('fs').promises;
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const config = require('./config');

const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');

const qrCodes = new Map();

const ThumbnailGenerator = require('video-thumbnail-generator').default;

const app = express();
const port = process.env.PORT || 8080;

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static('public'));

// Секретный ключ для JWT
const JWT_SECRET = crypto.randomBytes(64).toString('hex');

// Пользователь из конфига
const user = {
  id: 1,
  username: 'Atm4x',
  password: config.PASSWORD_HASH,
  role: 'admin'
};


// Middleware для проверки JWT
const authenticateJWT = (req, res, next) => {
    const token = req.cookies.token;
    console.log('Token from cookie:', token);
  
    if (token) {
      jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
          console.log('JWT verification failed:', err);
          return res.redirect('/');
        }
        req.user = user;
        console.log('User authenticated:', user);
        next();
      });
    } else {
      console.log('No token found, redirecting to login');
      res.redirect('/');
    }
  };

// Middleware для проверки роли
const checkRole = (role) => {
  return (req, res, next) => {
    if (req.user && req.user.role === role) {
      next();
    } else {
      res.status(403).send('Доступ запрещен');
    }
  };
};

const getDataDir = () => {
    let dir;
    if (process.env.NODE_ENV === 'production') {
      dir = '/app/data';
    } else {
      dir = path.join(__dirname, 'data');
    }
    // Убедимся, что директория существует
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    return dir;
  };

  const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      const dir = getDataDir();
      cb(null, dir);
    },
    filename: function (req, file, cb) {
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
      cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
  });

  const multerStorage = multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = getDataDir();
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
      cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
  });
  
  const multerFilter = (req, file, cb) => {
    // Разрешаем все типы файлов
    cb(null, true);
  };
  
  const upload = multer({
    storage: multerStorage,
    fileFilter: multerFilter
  });
  
app.post('/upload', authenticateJWT, (req, res) => {
  let uploadedFile = null;

  upload.single('file')(req, res, async function (err) {
    if (err) {
      console.error('Upload error:', err);
      return res.status(500).json({ error: 'Error uploading file: ' + err.message });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded.' });
    }

    uploadedFile = req.file;

    try {
      const originalName = req.file.originalname;
      const newPath = path.join(getDataDir(), originalName);
      
      await fs.promises.rename(req.file.path, newPath);
      console.log('File renamed to:', originalName);
      
      res.redirect('/dashboard');
    } catch (error) {
      console.error('Error renaming file:', error);
      res.status(500).json({ error: 'Error renaming file: ' + error.message });
    }
  });

  // Обработка прерванной загрузки
  req.on('aborted', () => {
    if (uploadedFile && uploadedFile.path) {
      fs.unlink(uploadedFile.path, (err) => {
        if (err) console.error('Error deleting incomplete file:', err);
        else console.log('Incomplete file deleted:', uploadedFile.path);
      });
    }
  });
});


  function saveTextFile() {
    const fileName = textFileName.value.trim();
    const content = textFileContent.value;
    
    if (!fileName) {
      alert('Пожалуйста, введите имя файла');
      return;
    }
    
    const endpoint = '/update-text-file';
    
    axios.post(endpoint, { fileName, content })
      .then(response => {
        if (response.data.success) {
          closeTextEditor();
          window.location.reload();
        } else {
          alert('Ошибка при сохранении файла: ' + (response.data.error || 'Неизвестная ошибка'));
        }
      })
      .catch(error => {
        console.error('Error:', error);
        alert('Произошла ошибка при сохранении файла: ' + (error.response?.data?.error || error.message));
      });
  }
    
  


  // Переименование файла
  app.post('/rename', authenticateJWT, async (req, res) => {
    const { oldName, newName } = req.body;
    
    if (!oldName || !newName || typeof oldName !== 'string' || typeof newName !== 'string') {
      return res.status(400).json({ success: false, error: 'Invalid file names' });
    }
  
    const dataDir = getDataDir();
    if (!dataDir) {
      return res.status(500).json({ success: false, error: 'Could not determine data directory' });
    }
  
    const oldPath = path.join(dataDir, oldName);
    const newPath = path.join(dataDir, newName);
  
    try {
      await fs.promises.rename(oldPath, newPath);
      console.log('File renamed from', oldName, 'to', newName);
      res.json({ success: true });
    } catch (err) {
      console.error('Error renaming file:', err);
      res.status(500).json({ success: false, error: 'Error renaming file: ' + err.message });
    }
  });

// Создание текстового файла
app.post('/create-text-file', authenticateJWT, (req, res) => {
  console.log('Received request to create text file:', req.body);
  
  const { fileName, content } = req.body;
  
  if (!fileName || typeof fileName !== 'string') {
    return res.status(400).json({ success: false, error: 'Invalid file name' + fileName + typeof fileName });
  }

  const dataDir = getDataDir();
  if (!dataDir) {
    return res.status(500).json({ success: false, error: 'Could not determine data directory' });
  }

  const filePath = path.join(dataDir, fileName);

  try {
    fs.promises.writeFile(filePath, content || '');
    console.log('Text file created:', filePath);
    res.json({ success: true });
  } catch (err) {
    console.error('Error creating text file:', err);
    res.status(500).json({ success: false, error: 'Error creating file: ' + err.message });
  }
});

// Обновление содержимого текстового файла
app.post('/update-text-file', authenticateJWT, async (req, res) => {
  const { fileName, content } = req.body;
  
  if (!fileName || typeof fileName !== 'string') {
    return res.status(400).json({ success: false, error: 'Invalid file name'});
  }

  const dataDir = getDataDir();
  if (!dataDir) {
    return res.status(500).json({ success: false, error: 'Could not determine data directory' });
  }

  const filePath = path.join(dataDir, fileName);

  try {
    await fs.promises.writeFile(filePath, content || '');
    console.log('Text file updated:', filePath);
    res.json({ success: true });
  } catch (err) {
    console.error('Error updating text file:', err);
    res.status(500).json({ success: false, error: 'Error updating file: ' + err.message });
  }
});

// Получение содержимого текстового файла
app.get('/get-text-file/:fileName', authenticateJWT, async (req, res) => {
  const fileName = req.params.fileName;
  const filePath = path.join(getDataDir(), fileName);

  try {
    const content = await fs.promises.readFile(filePath, 'utf-8');
    res.json({ success: true, content });
  } catch (err) {
    console.error('Error reading file:', err);
    res.status(500).json({ success: false, error: 'Error reading file' });
  }
});


app.get('/', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  const { username, password, remember } = req.body;
  const redirect = req.query.redirect || '/dashboard';

  if (username === user.username && await bcrypt.compare(password, user.password)) {
      const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { 
          expiresIn: remember ? '30d' : '1h' 
      });
      res.cookie('token', token, { 
          httpOnly: true, 
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: remember ? 30 * 24 * 60 * 60 * 1000 : undefined
      });
      res.redirect(redirect);
  } else {
      res.render('login', { error: 'Неверное имя пользователя или пароль.' });
  }
});

app.get('/dashboard', authenticateJWT, async (req, res) => {
    const dir = getDataDir();
    try {
      const files = await fsPromises.readdir(dir);
      res.render('dashboard', { files, username: req.user.username, role: req.user.role });
    } catch (err) {
      console.error(err);
      res.status(500).send('Ошибка чтения директории');
    }
  });
  
  app.get('/download/:filename', authenticateJWT, async (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(getDataDir(), filename);
  
    try {
      await fsPromises.access(filePath);
      res.download(filePath);
    } catch (err) {
      console.error(err);
      res.status(404).send('Файл не найден');
    }
  });
  
  app.post('/delete/:filename', authenticateJWT, async (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(getDataDir(), filename);
  
    try {
      await fsPromises.unlink(filePath);
      res.redirect('/dashboard');
    } catch (err) {
      console.error(err);
      res.status(500).send('Ошибка удаления файла');
    }
  });

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Что-то пошло не так!');
});

app.listen(port, () => {
  console.log(`Сервер запущен на http://localhost:${port}`);
});




function cleanupQRCodes() {
  const now = Date.now();
  for (const [key, value] of qrCodes.entries()) {
      if (now - value.createdAt > 5 * 60 * 1000) {
          qrCodes.delete(key);
      }
  }
}

setInterval(cleanupQRCodes, 5 * 60 * 1000);

app.get('/qr-login', (req, res) => {
  const qrId = uuidv4();
  const qrData = {
      id: qrId,
      createdAt: Date.now()
  };
  qrCodes.set(qrId, qrData);

  QRCode.toDataURL(`${req.protocol}://${req.get('host')}/confirm/${qrId}`, (err, url) => {
      if (err) {
          console.error('Error generating QR code:', err);
          return res.status(500).send('Error generating QR code');
      }
      res.render('qr-login', { qrCodeUrl: url });
  });
});

app.get('/confirm/:qrId', authenticateJWT, (req, res) => {
  const qrId = req.params.qrId;
  const qrData = qrCodes.get(qrId);

  if (!qrData) {
      return res.status(400).send('Invalid or expired QR code');
  }

  // Создаем новый токен для входа по QR-коду
  const token = jwt.sign({ id: req.user.id, username: req.user.username, role: req.user.role }, JWT_SECRET, { expiresIn: '1h' });

  // Удаляем использованный QR-код
  qrCodes.delete(qrId);

  res.json({ success: true, token });
});

app.get('/check-qr/:qrId', (req, res) => {
  const qrId = req.params.qrId;
  const qrData = qrCodes.get(qrId);

  if (!qrData) {
      return res.json({ status: 'expired' });
  }

  if (qrData.token) {
      qrCodes.delete(qrId);
      return res.json({ status: 'confirmed', token: qrData.token });
  }

  res.json({ status: 'pending' });
});
