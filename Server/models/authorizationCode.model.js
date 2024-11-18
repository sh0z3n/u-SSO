const authorizationCodeSchema = new mongoose.Schema({
    code: { type: String, required: true, unique: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    clientId: { type: String, required: true },
    scope: [{ type: String }],
    nonce: String,
    expiresAt: { type: Date, required: true },
    createdAt: { type: Date, default: Date.now }
  });
  // tho ig this schema is predefined in another model  as an entity

    const AuthorizationCode = mongoose.model('AuthorizationCode', authorizationCodeSchema);