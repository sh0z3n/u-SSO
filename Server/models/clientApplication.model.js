const clientApplicationSchema = new mongoose.Schema({
    name: { type: String, required: true },
  clientId: { type: String, required: true, unique: true },
  clientSecret: { type: String, required: true },
  redirectUris: [{ type: String }],
  allowedScopes: [{ type: String }],
  createdAt: { type: Date, default: Date.now }
});

const ClientApplication = mongoose.model('ClientApplication', clientApplicationSchema);