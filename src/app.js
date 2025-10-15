const express = require('express');
const cors = require('cors');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('./config/passport.config');
const restaurantsRouter = require('./routes/restaurants.routes');
const submissionsRouter = require('./routes/submissions.routes');
const authRouter = require('./routes/auth.routes');
const usersRouter = require('./routes/users.routes');
const notFound = require('./middleware/notFound.middleware');
const errorHandler = require('./middleware/error.middleware');
const mongoose = require('mongoose');
const getCorsConfig = require('../cors-config');

function createApp() {
  const app = express();
  
  // 프록시(예: Render, Vercel) 뒤에서 HTTPS 스킴을 신뢰하여 Secure 쿠키가 정상 설정되도록 함
  app.set('trust proxy', 1);

  // CORS 설정 - 로컬 개발 및 배포 환경 대응
  app.use(cors(getCorsConfig()));
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // 세션 설정
  const sessionConfig = {
    secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7일
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // HTTPS에서만 쿠키 전송
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    },
  };

  // 프록시 환경에서 set-cookie 처리 안정화
  if (process.env.NODE_ENV === 'production') {
    sessionConfig.proxy = true;
  }

  // MongoDB가 연결되어 있으면 MongoStore 사용, 아니면 메모리 세션 사용
  if (mongoose.connection.readyState === 1) {
    sessionConfig.store = MongoStore.create({
      client: mongoose.connection.getClient(),
      touchAfter: 24 * 3600, // 24시간 동안 세션 업데이트 방지
    });
  } else if (process.env.MONGODB_URI) {
    // MongoDB URI가 있으면 MongoStore 사용 (자동 연결)
    sessionConfig.store = MongoStore.create({
      mongoUrl: process.env.MONGODB_URI,
      dbName: process.env.DB_NAME,
      touchAfter: 24 * 3600,
    });
  }
  // 그 외의 경우 메모리 세션 사용 (개발/테스트 환경)

  app.use(session(sessionConfig));

  // Passport 초기화
  app.use(passport.initialize());
  app.use(passport.session());

  app.get('/health', (req, res) => {
    const state = mongoose.connection.readyState; // 0=disconnected,1=connected,2=connecting,3=disconnecting
    const dbStatus = {
      0: 'disconnected',
      1: 'connected', 
      2: 'connecting',
      3: 'disconnecting'
    };
    
    res.json({ 
      success: true,
      status: 'ok', 
      database: dbStatus[state],
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development'
    });
  });

  app.use('/api/auth', authRouter);
  app.use('/api/users', usersRouter);
  app.use('/api/restaurants', restaurantsRouter);
  app.use('/api/submissions', submissionsRouter);

  app.use(notFound);
  app.use(errorHandler);

  return app;
}

module.exports = createApp;