const firebase = require('firebase-admin');
const serviceAccount = require('./service-account-credentials.json');

const config = {
  credential: firebase.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL
}

const app = !firebase.apps.length ? firebase.initializeApp(config) : firebase.app();

// Policy helper function
const generatePolicy = (principalId, effect, resource) => {
  const authResponse = {};
  authResponse.principalId = principalId;
  if (effect && resource) {
    const policyDocument = {};
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = [];
    const statementOne = {};
    statementOne.Action = 'execute-api:Invoke';
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }
  return authResponse;
};

// Reusable Authorizer function, set on `authorizer` field in serverless.yml
module.exports.handler = (event, context, callback) => {
  console.log('event', event);

  if (!event.authorizationToken) {
    // No authorization token
    return callback('Unauthorized');
  }

  const tokenParts = event.authorizationToken.split(' ');
  const tokenValue = tokenParts[1];

  if (!(tokenParts[0].toLowerCase() === 'bearer' && tokenValue)) {
    // no auth token!
    return callback('Unauthorized');
  }

  try {
    app.auth().verifyIdToken(tokenValue)
      .then(function(decodedToken) {
        return callback(null, generatePolicy(decodedToken.sub, 'Allow', event.methodArn));
      }).catch(function(err) {
        console.log('catch error. Invalid token', err);
        return callback('Unauthorized');
      });

  } catch (err) {
    console.log('catch error. Invalid token', err);
    return callback('Unauthorized');
  }
};