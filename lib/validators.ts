import { body, query, param, validationResult } from 'express-validator';
import { type Request, type Response, type NextFunction } from 'express';

// Middleware to handle validation errors
export const validate = (req: Request, res: Response, next: NextFunction) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
};

// Auth Validators
export const loginValidator = [
    body('username').trim().toLowerCase().notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required'),
    validate,
];

export const registerValidator = [
    body('username')
        .trim()
        .toLowerCase()
        .isLength({ min: 3, max: 20 })
        .withMessage('Username must be between 3 and 20 characters')
        .matches(/^[a-z0-9_]+$/)
        .withMessage('Username can only contain lowercase letters, numbers, and underscores'),
    body('displayName')
        .optional()
        .trim()
        .escape()
        .isLength({ max: 50 })
        .withMessage('Display name must be less than 50 characters'),
    body('password')
        .isLength({ min: 6 })
        .withMessage('Password must be at least 6 characters long'),
    validate,
];

// Poop Log Validators
export const poopLogValidator = [
    body('notes').optional().trim().escape().isLength({ max: 1000 }),
    body('latitude').optional().isFloat({ min: -90, max: 90 }),
    body('longitude').optional().isFloat({ min: -180, max: 180 }),
    body('locationName').optional().trim().escape().isLength({ max: 100 }),
    body('photoUrl').optional().isURL().withMessage('Invalid photo URL'),
    body('rating').optional().isInt({ min: 1, max: 5 }),
    body('durationMinutes').optional().isInt({ min: 0, max: 1440 }),
    validate,
];

// Friend Request Validators
export const friendRequestValidator = [
    body('friendUsername').trim().toLowerCase().notEmpty().withMessage('Friend username is required'),
    validate,
];

export const friendRespondValidator = [
    body('friendshipId').isUUID().withMessage('Invalid friendship ID'),
    body('accept').isBoolean().withMessage('Accept must be a boolean'),
    validate,
];

// Search Validators
export const searchValidator = [
    query('query').trim().notEmpty().withMessage('Search query is required').escape(),
    validate,
];

// UUID Param Validator
export const uuidParamValidator = (paramName: string) => [
    param(paramName).isUUID().withMessage(`Invalid ${paramName}`),
    validate,
];
