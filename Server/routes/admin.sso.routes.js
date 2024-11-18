router.post('/applications', adminAuthMiddleware, async (req, res) => {
    try {
      const { name, redirectUris, allowedScopes } = req.body;
      
      const clientId = CryptoService.generateRandomString(24);
      const clientSecret = CryptoService.generateRandomString(48);
  
      const application = await ClientApplication.create({
        name,
        clientId,
        clientSecret,
        redirectUris,
        allowedScopes
      });
  
      res.status(201).json(application);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
  
  router.get('/applications', adminAuthMiddleware, async (req, res) => {
    try {
      const applications = await ClientApplication.find().select('-clientSecret');
      res.json(applications);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
  
//   const exemple = {
//     authorizationUrl: ,
//     tokenUrl: 
//     clientId: 
//     clientSecret: 
//     redirectUri: '',
//     scope: 
//   };