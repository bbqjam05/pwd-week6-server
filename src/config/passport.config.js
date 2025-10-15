// src/config/passport.config.js
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const NaverStrategy = require('passport-naver').Strategy;
const User = require('../models/user.model');

// 세션에 사용자 ID 저장
passport.serializeUser((user, done) => {
  done(null, user._id);
});

// 세션에서 사용자 ID로 사용자 객체 조회
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

// ==================== 로컬 전략 (이메일/비밀번호) ====================
passport.use(
  new LocalStrategy(
    {
      usernameField: 'email',
      passwordField: 'password',
    },
    async (email, password, done) => {
      try {
        // 사용자 찾기
        const user = await User.findOne({ email: email.toLowerCase(), provider: 'local' });
        
        if (!user) {
          return done(null, false, { message: '이메일 또는 비밀번호가 올바르지 않습니다.' });
        }

        // 비밀번호 확인
        const isMatch = await user.comparePassword(password);
        
        if (!isMatch) {
          return done(null, false, { message: '이메일 또는 비밀번호가 올바르지 않습니다.' });
        }

        // 계정 활성화 확인
        if (!user.isActive) {
          return done(null, false, { message: '비활성화된 계정입니다.' });
        }

        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  )
);

// ==================== 구글 OAuth 전략 ====================
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL || '/api/auth/google/callback',
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          console.log('[OAuth][Google] callback start', {
            id: profile && profile.id,
            email: Array.isArray(profile.emails) && profile.emails[0] && profile.emails[0].value,
          });
          // 기존 사용자 찾기
          let user = await User.findOne({
            provider: 'google',
            providerId: profile.id,
          });

          if (user) {
            // 기존 사용자 로그인
            console.log('[OAuth][Google] existing user', user._id);
            return done(null, user);
          }

          // 새 사용자 생성
          user = await User.create({
            provider: 'google',
            providerId: profile.id,
            email: profile.emails[0].value.toLowerCase(),
            name: profile.displayName,
            avatar: profile.photos && profile.photos[0] ? profile.photos[0].value : null,
          });

          console.log('[OAuth][Google] created user', user._id);
          return done(null, user);
        } catch (error) {
          console.error('[OAuth][Google] error', error);
          return done(error, null);
        }
      }
    )
  );
}

// ==================== 네이버 OAuth 전략 ====================
if (process.env.NAVER_CLIENT_ID && process.env.NAVER_CLIENT_SECRET) {
  passport.use(
    new NaverStrategy(
      {
        clientID: process.env.NAVER_CLIENT_ID,
        clientSecret: process.env.NAVER_CLIENT_SECRET,
        callbackURL: process.env.NAVER_CALLBACK_URL || '/api/auth/naver/callback',
        // 네이버 API에서 사용자 정보를 가져오는 엔드포인트
        profileURL: 'https://openapi.naver.com/v1/nid/me',
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          console.log('[OAuth][Naver] callback start - Full profile:', JSON.stringify(profile, null, 2));
          
          // 기존 사용자 찾기
          let user = await User.findOne({
            provider: 'naver',
            providerId: profile.id,
          });

          if (user) {
            // 기존 사용자 로그인
            console.log('[OAuth][Naver] existing user', user._id);
            return done(null, user);
          }

          // 네이버 프로필에서 이메일 추출
          let email = null;
          if (profile.emails && profile.emails.length > 0) {
            email = profile.emails[0].value.toLowerCase();
          } else if (profile._json && profile._json.email) {
            // 네이버 API 응답에서 직접 이메일 추출
            email = profile._json.email.toLowerCase();
          }
          
          // 이메일이 제공되지 않은 경우 providerId 기반의 placeholder 이메일 생성
          if (!email) {
            email = `naver_${profile.id}@placeholder.local`;
          }

          // 네이버 프로필에서 이름 추출
          let name = null;
          
          // 네이버 OAuth에서 제공하는 실제 필드명들 확인
          console.log('[OAuth][Naver] Available profile fields:', Object.keys(profile));
          console.log('[OAuth][Naver] Profile._json fields:', profile._json ? Object.keys(profile._json) : 'No _json');
          console.log('[OAuth][Naver] Profile._json content:', profile._json);
          
          // 네이버 API 응답 구조에 따른 이름 추출
          if (profile._json) {
            // 네이버 API 응답에서 직접 추출
            if (profile._json.name) {
              name = profile._json.name;
            } else if (profile._json.nickname) {
              name = profile._json.nickname;
            } else if (profile._json.id) {
              // 네이버 ID 사용 (일반적으로 더 깔끔함)
              name = profile._json.id;
            }
          }
          
          // Passport 프로필 객체에서 추출
          if (!name) {
            if (profile.displayName) {
              name = profile.displayName;
            } else if (profile.name) {
              name = profile.name;
            } else if (profile.username) {
              name = profile.username;
            }
          }
          
          // 여전히 이름을 찾지 못한 경우
          if (!name) {
            // 네이버 ID를 사용하거나 기본값 사용
            name = profile._json?.id || `네이버사용자_${profile.id}`;
          }
          
          console.log('[OAuth][Naver] Extracted name:', name);

          // 네이버 프로필에서 아바타 추출
          let avatar = null;
          if (profile.photos && profile.photos.length > 0) {
            avatar = profile.photos[0].value;
          } else if (profile._json && profile._json.profile_image) {
            avatar = profile._json.profile_image;
          }

          console.log('[OAuth][Naver] Creating user with data:', {
            provider: 'naver',
            providerId: profile.id,
            email,
            name,
            avatar,
            'profile._json': profile._json,
            'profile keys': Object.keys(profile)
          });

          // 새 사용자 생성
          user = await User.create({
            provider: 'naver',
            providerId: profile.id,
            email,
            name,
            avatar,
          });

          console.log('[OAuth][Naver] created user successfully:', user._id);
          return done(null, user);
        } catch (error) {
          console.error('[OAuth][Naver] error details:', error);
          return done(error, null);
        }
      }
    )
  );
}

module.exports = passport;
