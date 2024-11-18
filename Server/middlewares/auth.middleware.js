const { error } = require("console");
const CryptoService = require("../services/crypto-service.js");

const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) {
            throw new error('ulach token')
        }
        const token = authHeader.split(' ')[1];
        // console.log(token);
        const decoded = CryptoService.verifyJWT(token,oidcConfig.clientSecret);
        const tokenRecord = await Token.findOne({userId : decoded.userId, accessToken : token});
        if (!tokenRecord) {
            throw new error('Invalid token');
        }
        req.user = await User.findbyId (tokenRecord.userId) 
        req.token = tokenRecord;
        next();
    }catch(Error) {
        res.status(401).send('Unauthorized');
    }
};

