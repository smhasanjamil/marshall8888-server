import { Document, Model } from 'mongoose';

// Enum for User Roles
export enum UserRole {
   ADMIN = 'admin',
   USER = 'user'
}

// User Schema Definition
export interface IUser extends Document {
   email: string;
   password: string;
   firstName: string;
   lastName: string;
   role: UserRole;
   isActive: boolean;
   otpToken?: string | null;
   createdAt: Date;
   updatedAt: Date;
}

export interface UserModel extends Model<IUser> {
   //instance methods for checking if passwords are matched
   isPasswordMatched(
      plainTextPassword: string,
      hashedPassword: string
   ): Promise<boolean>;
   isUserExistsByEmail(id: string): Promise<IUser>;
   checkUserExist(userId: string): Promise<IUser>;
}