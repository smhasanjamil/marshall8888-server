// import { IUser, UserRole } from './user.interface';
// import User from './user.model';
// import AppError from '../../errors/appError';
// import { status } from 'http-status-codes';
// import QueryBuilder from '../../builder/QueryBuilder';
// import { UserSearchableFields } from './user.constant';
// import Customer from '../customer/customer.model';
// import mongoose from 'mongoose';
// import { IImageFile } from '../../interface/IImageFile';
// import { AuthService } from '../auth/auth.service';
// import { ICustomer } from '../customer/customer.interface';
// import { IJwtPayload } from '../auth/auth.interface';

import { IUser } from "./user.interface";
import { UserSearchableFields } from "./user.constant";
import { User } from "./user.model";
import QueryBuilder from "../../builder/QueryBuilder";
import AppError from "../../errors/appError";
import status from "http-status";
import { IJwtPayload } from "../auth/auth.interface";

// Function to register user
const registerUser = async (userData: IUser) => {
  // Check if user already exists
  const user = await User.findOne({ email: userData.email });
  if (user) {
    throw new AppError(status.CONFLICT, "Email is already registered.");
  }

  // Create and save the user
  const result = await User.create(userData);

  return result;
};

const getAllUser = async (query: Record<string, unknown>) => {
  const UserQuery = new QueryBuilder(User.find(), query)
    .search(UserSearchableFields)
    .filter()
    .sort()
    .paginate()
    .fields();

  const result = await UserQuery.modelQuery;
  const meta = await UserQuery.countTotal();
  return {
    result,
    meta,
  };
};

const myProfile = async (authUser: IJwtPayload) => {
  const isUserExists = await User.findById(authUser.userId);
  if (!isUserExists) {
    throw new AppError(status.NOT_FOUND, "User not found!");
  }
  if (!isUserExists.isActive) {
    throw new AppError(status.BAD_REQUEST, "User is not active!");
  }

  const profile = await Customer.findOne({ user: isUserExists._id });

  return {
    ...isUserExists.toObject(),
    profile: profile || null,
  };
};

const updateProfile = async (
  payload: Partial<IUser>,
  //   file: IImageFile,
  authUser: IJwtPayload
) => {
  const isUserExists = await User.findById(authUser.userId);

  if (!isUserExists) {
    throw new AppError(status.NOT_FOUND, "User not found!");
  }
  if (!isUserExists.isActive) {
    throw new AppError(status.BAD_REQUEST, "User is not active!");
  }

  //   if (file && file.path) {
  //     payload.photo = file.path;
  //   }

  const result = await Customer.findOneAndUpdate(
    { user: authUser.userId },
    payload,
    {
      new: true,
    }
  ).populate("user");

  return result;
};

const updateUserStatus = async (userId: string) => {
  const user = await User.findById(userId);

  console.log("comes here");
  if (!user) {
    throw new AppError(status.NOT_FOUND, "User is not found");
  }

  user.isActive = !user.isActive;
  const updatedUser = await user.save();
  return updatedUser;
};

export const UserServices = {
  registerUser,
  getAllUser,
  myProfile,
  updateUserStatus,
  updateProfile,
};
