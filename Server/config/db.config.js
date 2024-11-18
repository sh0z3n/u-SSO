const dbConfig = {
    url : procrss.env.MONGODB_URI || 'mongodb://localhost:1337/somedbidgf',
    options: {
        useNewUrlParser: true,
        useUnifiedTopology: true
    }
};