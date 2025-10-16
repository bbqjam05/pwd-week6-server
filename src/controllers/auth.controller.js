// src/controllers/auth.controller.js
const passport = require('passport');
const authService = require('../services/auth.service');
const asyncHandler = require('../utils/asyncHandler');

class AuthController {
  /**
   * 회원가입
   * POST /api/auth/register
   */
  register = asyncHandler(async (req, res) => {
    const { email, password, name } = req.body;

    // 유효성 검사
    if (!email || !password || !name) {
      return res.status(400).json({
        success: false,
        message: '이메일, 비밀번호, 이름은 필수입니다.',
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: '비밀번호는 최소 6자 이상이어야 합니다.',
      });
    }

    const user = await authService.register({ email, password, name });

    // 회원가입 후 자동 로그인
    req.login(user, (err) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: '회원가입 후 로그인 중 오류가 발생했습니다.',
        });
      }

      res.status(201).json({
        success: true,
        message: '회원가입이 완료되었습니다.',
        data: { user },
      });
    });
  });

  /**
   * 로컬 로그인
   * POST /api/auth/login
   */
  login = (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: '로그인 중 오류가 발생했습니다.',
        });
      }

      if (!user) {
        return res.status(401).json({
          success: false,
          message: info.message || '로그인에 실패했습니다.',
        });
      }

      req.login(user, (err) => {
        if (err) {
          return res.status(500).json({
            success: false,
            message: '로그인 중 오류가 발생했습니다.',
          });
        }

        return res.json({
          success: true,
          message: '로그인되었습니다.',
          data: { user },
        });
      });
    })(req, res, next);
  };

  /**
   * 로그아웃
   * POST /api/auth/logout
   */
  logout = asyncHandler(async (req, res) => {
    req.logout((err) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: '로그아웃 중 오류가 발생했습니다.',
        });
      }

      req.session.destroy((err) => {
        if (err) {
          return res.status(500).json({
            success: false,
            message: '세션 삭제 중 오류가 발생했습니다.',
          });
        }

        res.clearCookie('connect.sid');
        res.json({
          success: true,
          message: '로그아웃되었습니다.',
        });
      });
    });
  });

  /**
   * 현재 사용자 정보 조회
   * GET /api/auth/me
   */
  getCurrentUser = asyncHandler(async (req, res) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: '로그인이 필요합니다.',
      });
    }

    const user = await authService.getCurrentUser(req.user._id);

    res.json({
      success: true,
      data: { user },
    });
  });


  // ✨✨✨ 새로 추가된 부분 시작 ✨✨✨
  /**
   * Google OAuth 인증 URL 생성
   * GET /api/auth/google/url
   */
  getGoogleAuthUrl = (req, res) => {
    const rootUrl = 'https://accounts.google.com/o/oauth2/v2/auth';
    const options = {
      redirect_uri: process.env.GOOGLE_CALLBACK_URL,
      client_id: process.env.GOOGLE_CLIENT_ID,
      access_type: 'offline',
      response_type: 'code',
      prompt: 'consent',
      scope: [
        'https://www.googleapis.com/auth/userinfo.profile',
        'https://www.googleapis.com/auth/userinfo.email',
      ].join(' '),
    };
    const qs = new URLSearchParams(options);
    res.json({ url: `${rootUrl}?${qs.toString()}` });
  };

  /**
   * Naver OAuth 인증 URL 생성
   * GET /api/auth/naver/url
   */
  getNaverAuthUrl = (req, res) => {
    const rootUrl = "https://nid.naver.com/oauth2.0/authorize";
    const options = {
      response_type: 'code',
      client_id: process.env.NAVER_CLIENT_ID,
      redirect_uri: process.env.NAVER_CALLBACK_URL,
      state: 'RANDOM_STATE' // CSRF 공격 방지를 위한 상태 토큰 (실제로는 랜덤 생성 필요)
    };
    const qs = new URLSearchParams(options);
    res.json({ url: `${rootUrl}?${qs.toString()}` });
  };
  // ✨✨✨ 새로 추가된 부분 끝 ✨✨✨


  /**
   * 구글 OAuth 콜백
   * GET /api/auth/google/callback
   */
  googleCallback = (req, res, next) => {
    passport.authenticate('google', (err, user, info) => {
      if (err) {
        return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}/login?error=server_error`);
      }

      if (!user) {
        return res.redirect(
          `${process.env.CLIENT_URL || 'http://localhost:3000'}/login?error=${encodeURIComponent(
            info.message || '로그인 실패'
          )}`
        );
      }

      req.login(user, (err) => {
        if (err) {
          return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}/login?error=login_error`);
        }

        return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}/dashboard`);
      });
    })(req, res, next);
  };

  /**
   * 네이버 OAuth 콜백
   * GET /api/auth/naver/callback
   */
  naverCallback = (req, res, next) => {
    passport.authenticate('naver', (err, user, info) => {
      console.log('[Naver Callback] Error:', err);
      console.log('[Naver Callback] User:', user);
      console.log('[Naver Callback] Info:', info);
      
      if (err) {
        console.error('[Naver Callback] Authentication error:', err);
        return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}/login?error=server_error`);
      }

      if (!user) {
        console.error('[Naver Callback] No user found:', info);
        return res.redirect(
          `${process.env.CLIENT_URL || 'http://localhost:3000'}/login?error=${encodeURIComponent(
            info.message || '로그인 실패'
          )}`
        );
      }

      req.login(user, (err) => {
        if (err) {
          console.error('[Naver Callback] Login error:', err);
          return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}/login?error=login_error`);
        }

        console.log('[Naver Callback] Successfully logged in user:', user._id);
        return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}/dashboard`);
      });
    })(req, res, next);
  };

}

module.exports = new AuthController();
