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
const ThumbnailGenerator = require('video-thumbnail-generator').default;

const app = express();
const port = process.env.PORT || 8080;

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
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
    destination: (req, file, cb) => {
      const dir = getDataDir();
      cb(null, dir);
    },
    filename: (req, file, cb) => {
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
    let uploadedFile;
  
    upload.single('file')(req, res, async function (err) {
      if (err instanceof multer.MulterError) {
        console.error('Multer error:', err);
        return res.status(500).send('Ошибка при загрузке файла: ' + err.message);
      } else if (err) {
        console.error('Unknown error:', err);
        return res.status(500).send('Произошла неизвестная ошибка при загрузке файла');
      }
  
      if (!req.file) {
        return res.status(400).send('Файл не был загружен.');
      }
  
      uploadedFile = req.file;
  
      // Генерация thumbnail для видео
      if (req.file.mimetype.startsWith('video/')) {
        try {
          const tg = new ThumbnailGenerator({
            sourcePath: req.file.path,
            thumbnailPath: path.join(getDataDir(), 'thumbnails')
          });
  
          const thumbnail = await tg.generateThumbnail({ percentage: 10 });
          console.log('Thumbnail generated:', thumbnail);
        } catch (error) {
          console.error('Error generating thumbnail:', error);
        }
      }
  
      console.log('File uploaded successfully:', req.file);
      res.redirect('/dashboard');
    });
  
    // Обработка прерванной загрузки
    req.on('aborted', () => {
      if (uploadedFile) {
        fs.unlink(uploadedFile.path, (err) => {
          if (err) console.error('Error deleting incomplete file:', err);
          else console.log('Incomplete file deleted:', uploadedFile.path);
        });
      }
    });
  });

app.get('/', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
  
    if (username === user.username && await bcrypt.compare(password, user.password)) {
      const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
      res.cookie('token', token, { 
        httpOnly: true, 
        secure: process.env.NODE_ENV === 'production' ? false : true,
        sameSite: 'strict'
      });
      res.redirect('/dashboard');
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