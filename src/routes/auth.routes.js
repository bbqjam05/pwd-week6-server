// src/routes/auth.routes.js
const express = require('express');
const passport = require('passport');
const authController = require('../controllers/auth.controller');
const { isAuthenticated, isNotAuthenticated } = require('../middleware/auth.middleware');

const router = express.Router();

// ==================== 로컬 인증 ====================
// 회원가입
router.post('/register', isNotAuthenticated, authController.register);

// 로그인
router.post('/login', isNotAuthenticated, authController.login);

// 로그아웃
router.post('/logout', isAuthenticated, authController.logout);

// 현재 사용자 정보
router.get('/me', isAuthenticated, authController.getCurrentUser);

// ==================== 구글 OAuth ====================
// 구글 로그인 시작
router.get(
  '/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
  })
);

// 구글 콜백
router.get('/google/callback', authController.googleCallback);

// ==================== 네이버 OAuth ====================
// 네이버 로그인 시작
router.get(
  '/naver',
  passport.authenticate('naver')
);

// 네이버 콜백
router.get('/naver/callback', authController.naverCallback);

module.exports = router;
