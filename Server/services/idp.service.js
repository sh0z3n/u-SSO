import { constants } from 'constants';
import mongoose from 'mongoose';


class IdentityProviderService {
    constructor(config) {   
        this.config = config;
        this.User = mongoose.model('User');
    }
    async validateClient(redirectUri) {
        return (
            this.config.clients &&
            this.config.redirectUris.includes(redirectUri)
        );
    }
    async generateAuthCode(userId, clientId, scope) {
        const authCode = this.cryptoService.generateRandomString(32);
        await Token.create({
            userId,
            clientId,
            authCode,
            scope,
            expiresAt: new Date(Date.now() + 600000)
        });
        return authCode;
        
    }
    async generateTokens(authCode) {
        const tokenRecord = await Token.findOne({ authCode });
        if (!tokenRecord) {
            throw new Error('Invalid auth code');
        }
        const accessToken = CryptoService.generateJWT({ 
            userId : tokenRecord.userId,
            scope : tokenRecord.scope},
            this.config.clientSecret,
            {expiresIn : '1h'}
        );
        const refreshToken = CryptoService.generateRandomString(32);
        

        await Token.findOneAndUpdate (
            tokenRecord._id,
            {accessToken, refreshToken, authCode: null});

        return {accessToken, refreshToken};

    }

    async refreshTokens(refreshToken) {
        const tokenRecord = await Token.findOne({ refreshToken });
        if (!tokenRecord) {
            throw new Error('Invalid refresh token');
        }
        const accessToken = CryptoService.generateJWT({ 
            userId : tokenRecord.userId,
            scope : tokenRecord.scope},
            this.config.clientSecret,
            {expiresIn : '1h'}
        );
        const newRefreshToken = CryptoService.generateRandomString(32);

        await Token.findOneAndUpdate (
            tokenRecord._id,
            {accessToken, refreshToken: newRefreshToken});
        
        return {accessToken, refreshToken: newRefreshToken};

    }}

     