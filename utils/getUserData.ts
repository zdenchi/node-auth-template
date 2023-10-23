import { User, Profile } from '../controllers/auth.controller'

export const getUserData = (user: User, profile: Profile) => {
  return {
    id: user.id,
    username: user.username,
    phone: user.phone,
    email: user.email,
    firstname: profile.firstname,
    lastname: profile.lastname,
    middlename: profile.middlename,
    birthdate: profile.birthday,
    gender: profile.gender,
    country: profile.country,
    city: profile.city,
  };
};
