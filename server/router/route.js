import { Router } from "express";
const router = Router();

/** import all controllers */
import * as controller from '../controllers/appController.js';
// import * as controller from '../controllers/appControllerChandra.js';
import { registerMail } from '../controllers/mailer.js'
import Auth, { localVariables } from '../middleware/auth.js';




// router.route('/register').post((req, res) => res.json('register route success'))
// router.get('/ayush', (req, res) => res.json('ayush route welocome YOU'))
// router.route('/kumar').get((req, res) => res.json('kumar is my 2nd name'))

router.route('/register').post(controller.register)
router.route('/registerMail').post(registerMail)
router.route('/authenticate').post(controller.verifyUser, (req, res) => res.end())
router.route('/login').post( controller.verifyUser,controller.login)

router.route('/user/:username').get(controller.getUser)
router.route('/generateOTP').get(controller.verifyUser, localVariables, controller.generateOTP)
router.route('/verifyOTP').get(controller.verifyUser, controller.verifyOTP)
router.route('/createResetSession').get(controller.createResetSession)

router.route('/updateuser').put(Auth, controller.updateuser)
router.route('/resetPassword').put(controller.verifyUser, controller.resetPassword)







/** POST Methods */
// router.route('/register').post((req, res) => res.json('register route'))
// router.route('/register').post(controller.register); // register user
// router.route('/registerMail').post(registerMail); // send the email
// router.route('/authenticate').post(controller.verifyUser, (req, res) => res.end()); // authenticate user
// router.route('/login').post(controller.verifyUser,controller.login); // login in app

/** GET Methods */
// router.route('/user/:username').get(controller.getUser) // user with username
// router.route('/generateOTP').get(controller.verifyUser, localVariables, controller.generateOTP) // generate random OTP
// router.route('/verifyOTP').get(controller.verifyUser, controller.verifyOTP) // verify generated OTP
// router.route('/createResetSession').get(controller.createResetSession) // reset all the variables


/** PUT Methods */
// router.route('/updateuser').put(Auth, controller.updateUser); // is use to update the user profile
// router.route('/resetPassword').put(controller.verifyUser, controller.resetPassword); // use to reset password



export default router;