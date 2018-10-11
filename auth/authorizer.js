const firebase = require('firebase-admin');
const serviceAccount = require('./service-account-credentials.json');

// every configuration is set in an env variable for security reasons https://firebase.google.com/docs/admin/setup
const config = {
  credential: firebase.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL,
};

const app = !firebase.apps.length ? firebase.initializeApp(config) : firebase.app();

/**
 * Function used to build the authorization response in the Lambda way
 * attacching the necessary info (policy, statement, principalId)
 */
const generatePolicy = (principalId, effect, resource) => {
  const authResponse = {};
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
  if (principalId.devMessage) {
    authResponse.context = principalId;
  } else {
    authResponse.principalId = principalId;
  }
  return authResponse;
};

/**
 * This lambda function is used as `authorizer`.
 * It handles the authentication with firebase and its job is to authenticate each and every call.
 * Set it in the 'authorize' field in serverless.yml
 */
module.exports.handler = (event, context, callback) => {
  console.log('event', event);
  context.callbackWaitsForEmptyEventLoop = false;

  if (!event.authorizationToken) {
    // No authorization token
    return callback('Missing authorization token.');
  }

  const tokenParts = event.authorizationToken.split(' ');
  const tokenValue = tokenParts[1];

  if (!(tokenParts[0].toLowerCase() === 'bearer' && tokenValue)) {
    // no auth token!
    return callback('Malformed authorization token.');
  }

  try {
    // Verify the token and check if it's been revoked
    const decodedToken = await app.auth().verifyIdToken(tokenValue, true);

    // Sub is the firebase field containing the user/device id
    const generatedPolicy = generatePolicy(decodedToken.sub, 'Allow', event.methodArn);
    return callback(null, generatedPolicy);
  } catch (err) {
    console.log('catch error. Invalid token', err);
    return callback('There are some issues with your auth token.');
  }
};
