class SSOservice {
    static async getValidSession(req) {
        const sessionToken = req.cookies['sso_session'];
    if (!sessionToken) return null;

    return await SSOSession.findOne({
      token: sessionToken,
      expiresAt: { $gt: new Date() }
    });
  }



    static async generateAuthCode({ userId, clientId, scope, nonce }) {
    const code = CryptoService.generateRandomString(32);
    
    await AuthorizationCode.create({
      code,
      userId,
      clientId,
      scope,
      nonce,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
    });

    return code;
  }

  static async exchangeAuthCode(code, clientApp) {
    // validate auth code
    const authCode = await AuthorizationCode.findOne({ 
      code,
      clientId: clientApp.clientId,
      expiresAt: { $gt: new Date() }
    });
    if (!authCode) throw new Error('Invalid authorization code');

    const user = await User.findById(authCode.userId);
    if (!user) throw new Error('User not found');

    const accessToken = await TokenService.generateAccessToken({
      sub: user.id,
      clientId: clientApp.clientId,
      scope: authCode.scope
    });

    const idToken = await TokenService.generateIdToken({
      sub: user.id,
      nonce: authCode.nonce,
      auth_time: Math.floor(authCode.createdAt.getTime() / 1000),
      name: user.name,
      email: user.email
    }, clientApp);

    const refreshToken = await TokenService.generateRefreshToken(user.id, clientApp.clientId);

    await AuthorizationCode.deleteOne({ _id: authCode._id });

    return { accessToken, idToken, refreshToken };
  }

  static async createSSOSession(userId) {
    const token = CryptoService.generateRandomString(32);
    
    await SSOSession.create({
      userId,
      token,
      expiresAt: new Date(Date.now() + 8 * 60 * 60 * 1000) // 8 hours
    });

    return token;
  }
}