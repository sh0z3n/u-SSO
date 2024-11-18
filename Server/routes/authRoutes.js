// this route is the resp of the sso authentication
const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const IdentityProviderService = require('../services/idp.service');
const idpService = new IdentityProviderService(oidcConfig);
const ClientApplication = require('../models/clientApplication.model');
const SSOSession = require('../models/ssoSession.model');
// if u want to add some emailing service i have a ready one in my uventlo rep , in this app there ain't
const csrfProtection = csrf({ cookie: true });
const authLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 20, // limit each IP to 20 requests 
    message: 'Too many requests from this IP, please try again later.',
  });


// metadata endpoint

router.get('/metadata', async (req, res) => {
    try {
        // return saml/oidc for sp configuration
        const meta = {
            issuer: oidcConfig.issuer,
            authorization_endpoint: `${oidcConfig.issuer}/authorize`,
            token_endpoint: `${oidcConfig.issuer}/token`,
            userinfo_endpoint: `${oidcConfig.issuer}/userinfo`,
            jwks_uri: `${oidcConfig.issuer}/jwks`,
            scopes_supported: ['openid', 'profile', 'email'],
            response_types_supported: ['code', 'token', 'id_token'],
            grant_types_supported: ['authorization_code', 'implicit', 'refresh_token'],
            token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
            claims_supported: ['sub', 'name', 'email', 'email_verified'],
            code_challenge_methods_supported: ['S256']
        }
        res.json(meta);
    } catch (err) {
        res.status(500).send('Error while fetching metadata');
    }

});




// @desc : auth endpoint
router.get('/authorize' , async (req, res) => {
    try {
        const { client_id, redirect_uri, response_type, scope, nonce } = req.query;
        if (!client_id || !redirect_uri || response_type !== 'code' || !scope) {
            throw new Error('Missing required parameters');
        }
        const clientApp = await ClientApplication.findOne({ clientId: client_id });
        if (!clientApp || !clientApp.redirectUris.includes(redirect_uri)) {
          throw new Error('Invalid client application');
        }
        const session = await SSOSession.create({ userId: req.user.id });
        if (SsoSession && prompt !=='login') {const authCode = await SSOService.generateAuthCode({
            userId: ssoSession.userId,
            clientId: client_id,
            scope,
            nonce
          });
    
          const redirectUrl = new URL(redirect_uri);
          redirectUrl.searchParams.append('code', authCode);
          if (state) redirectUrl.searchParams.append('state', state);
          
          return res.redirect(redirectUrl.toString());
        }

        req.session.authRequest = {
            clientId: client_id,
            redirectUri: redirect_uri,
            scope,
            state,
            nonce
          };    
        
        res.redirect('/auth/login');}
    catch(err) {
        throw new Error('Error accured while authorizing');
    }});


// @desc : token endpointrouter.post('/token', async (req, res) => {
  try {
    const { grant_type, code, refresh_token, client_id, client_secret } = req.body;

    const clientApp = await ClientApplication.findOne({ 
      clientId: client_id,
      clientSecret: client_secret 
    });
    if (!clientApp) {
      throw new Error('Invalid client credentials');
    }

    let tokens;
    if (grant_type === 'authorization_code') {
      tokens = await SSOService.exchangeAuthCode(code, clientApp);
    } else if (grant_type === 'refresh_token') {
      tokens = await SSOService.refreshTokens(refresh_token, clientApp);
    } else {
      throw new Error('Invalid grant type');
    }

    res.json({
      access_token: tokens.accessToken,
      id_token: tokens.idToken,
      refresh_token: tokens.refreshToken,
      token_type: 'Bearer',
      expires_in: 3600
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
;
router.post('/forgot-password', authLimiter, async (req, res) => {
    try {
      const { email } = req.body;
      const user = await User.findOne({ email });
      
      if (user) {
        const resetToken = CryptoService.generateRandomString();
        await Token.create({
          userId: user._id,
          type: 'password_reset',
          token: resetToken,
          expiresAt: new Date(Date.now() + 1 * 60 * 60 * 1000) // 1 hour
        });
  
        await EmailService.sendPasswordResetEmail(email, resetToken);
      }
  
      res.json({ message: 'If an account exists, a password reset email has been sent.' });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  router.post('/reset-password/:token', authLimiter, async (req, res) => {
    try {
      const { token } = req.params;
      const { password } = req.body;
  
      const resetToken = await Token.findOne({
        token,
        type: 'password_reset',
        expiresAt: { $gt: new Date() }
      });
  
      if (!resetToken) {
        return res.status(400).json({ error: 'Invalid or expired reset token' });
      }
  
      const hashedPassword = await CryptoService.hashPassword(password);
      await User.findByIdAndUpdate(resetToken.userId, { password: hashedPassword });
      await Token.deleteOne({ _id: resetToken._id });
  
      res.json({ message: 'Password reset successful' });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  router.get('/profile', authenticateToken, async (req, res) => {
    try {
      const user = await User.findById(req.user._id).select('-password');
      res.json(user);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });