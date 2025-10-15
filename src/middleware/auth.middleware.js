// src/middleware/auth.middleware.js

/**
 * 로그인 확인 미들웨어
 */
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }

  return res.status(401).json({
    success: false,
    message: '로그인이 필요합니다.',
  });
};

/**
 * 로컬 계정 확인 미들웨어 (비밀번호 변경 등에 사용)
 */
const isLocalAccount = (req, res, next) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({
      success: false,
      message: '로그인이 필요합니다.',
    });
  }

  if (req.user.provider !== 'local') {
    return res.status(403).json({
      success: false,
      message: '로컬 계정만 사용할 수 있는 기능입니다.',
    });
  }

  return next();
};

/**
 * 로그인 안 된 상태 확인 미들웨어 (회원가입, 로그인 페이지 접근용)
 */
const isNotAuthenticated = (req, res, next) => {
  if (!req.isAuthenticated()) {
    return next();
  }

  return res.status(400).json({
    success: false,
    message: '이미 로그인되어 있습니다.',
  });
};

/**
 * 관리자 권한 확인 미들웨어
 */
const isAdmin = (req, res, next) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({
      success: false,
      message: '로그인이 필요합니다.',
    });
  }

  if (req.user.userType !== 'admin') {
    return res.status(403).json({
      success: false,
      message: '관리자 권한이 필요합니다.',
    });
  }

  return next();
};

module.exports = {
  isAuthenticated,
  isLocalAccount,
  isNotAuthenticated,
  isAdmin,
};
