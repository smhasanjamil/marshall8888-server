import { z } from "zod";
import { UserRole } from "./user.interface";

const userValidationSchema = z.object({
  body: z.object({
    firstName: z.string({ required_error: "First name is required" }),
    lastName: z.string({ required_error: "Last name is required" }),
    email: z
      .string({ required_error: "Email is required" })
      .email("Invalid email"),
    password: z
      .string({ required_error: "Password is required" })
      .min(6, "Password must be at least 6 characters"),
    role: z.nativeEnum(UserRole, {
      required_error: "Role is required",
      invalid_type_error: "Invalid role",
    }),
    isActive: z.boolean().optional().default(true),
    otpToken: z.string().optional().nullable(),
  }),
});

export const updateUserValidationSchema = z.object({
  body: z.object({
    firstName: z.string().optional(),
    lastName: z.string().optional(),
    email: z.string().email("Invalid email").optional(),
    role: z.nativeEnum(UserRole).optional(),
    isActive: z.boolean().optional(),
  }),
});

export const UserValidation = {
  userValidationSchema,
  updateUserValidationSchema,
};
