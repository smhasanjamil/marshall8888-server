import { Router } from "express";
import validateRequest from "../../middleware/validateRequest";
import { UserValidation } from "./user.validation";
import { UserRole } from "./user.interface";
import auth from "../../middleware/auth";
import { UserController } from "./user.controller";

const router = Router();

router.get("/", UserController.getAllUser);

router.get("/me", UserController.myProfile);

router.post(
  "/",
  validateRequest(UserValidation.userValidationSchema),
  UserController.registerUser
);
// update profile
router.patch(
  "/update-profile",

  // multerUpload.single('profilePhoto'),
  // parseBody,
  validateRequest(UserValidation.updateUserValidationSchema),
  UserController.updateProfile
);

router.patch(
  "/:id/status",
  // auth(UserRole.ADMIN),
  UserController.updateUserStatus
);

export const UserRoutes = router;
