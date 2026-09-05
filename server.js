// ============================================================
// S.C.A.G.S.S STAFF PORTAL V1
// COMPLETE BACKEND SERVER
//
// Features:
// - Secure login
// - Teacher accounts
// - Admin accounts
// - Password hashing
// - Attendance clock-in
// - Attendance clock-out
// - Server-side GPS verification
// - 500 metre geofence
// - GPS coordinates stored at clock-in/out
// - GPS accuracy stored
// - Distance from school stored
// - Admin can view teacher GPS records
// - Admin staff management
// - Attendance reports
// - GPS settings
// ============================================================

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");

const app = express();

// ============================================================
// CONFIGURATION
// ============================================================

const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
    console.error("ERROR: DATABASE_URL is missing.");
    process.exit(1);
}

if (!process.env.JWT_SECRET) {
    console.error("ERROR: JWT_SECRET is missing.");
    process.exit(1);
}


// ============================================================
// DATABASE CONNECTION
// ============================================================

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,

    ssl: {
        rejectUnauthorized: false
    }
});


// ============================================================
// MIDDLEWARE
// ============================================================

app.use(
    helmet({
        crossOriginResourcePolicy: false
    })
);

app.use(
    cors({
        origin: process.env.FRONTEND_URL || true,
        credentials: true
    })
);

app.use(express.json());

app.use(
    express.urlencoded({
        extended: true
    })
);

app.use(cookieParser());


// ============================================================
// LOGIN RATE LIMIT
// ============================================================

const loginLimiter = rateLimit({

    windowMs: 15 * 60 * 1000,

    max: 10,

    message: {
        success: false,
        message:
            "Too many login attempts. Please try again later."
    }

});


// ============================================================
// HEALTH CHECK
// ============================================================

app.get("/api/health", async (req, res) => {

    try {

        await pool.query("SELECT NOW()");

        res.json({

            success: true,

            message:
                "S.C.A.G.S.S STAFF PORTAL API is running.",

            database: "connected"

        });

    } catch (error) {

        console.error("DATABASE ERROR:", error);

        res.status(500).json({

            success: false,

            message:
                "Database connection failed."

        });

    }

});


// ============================================================
// JWT TOKEN
// ============================================================

function createToken(user) {

    return jwt.sign(

        {
            id: user.id,

            username: user.username,

            role: user.role

        },

        process.env.JWT_SECRET,

        {
            expiresIn: "8h"
        }

    );

}


// ============================================================
// AUTHENTICATION
// ============================================================

function authenticate(req, res, next) {

    try {

        let token =
            req.cookies.scagss_token;


        // Authorization header support

        if (
            !token &&
            req.headers.authorization
        ) {

            const parts =
                req.headers.authorization.split(" ");

            if (
                parts.length === 2 &&
                parts[0] === "Bearer"
            ) {

                token = parts[1];

            }

        }


        if (!token) {

            return res.status(401).json({

                success: false,

                message:
                    "Authentication required."

            });

        }


        const decoded =
            jwt.verify(
                token,
                process.env.JWT_SECRET
            );


        req.user = decoded;

        next();

    } catch (error) {

        return res.status(401).json({

            success: false,

            message:
                "Invalid or expired session."

        });

    }

}


// ============================================================
// ADMIN AUTHORIZATION
// ============================================================

function requireAdmin(req, res, next) {

    if (!req.user) {

        return res.status(401).json({

            success: false,

            message:
                "Authentication required."

        });

    }


    if (req.user.role !== "admin") {

        return res.status(403).json({

            success: false,

            message:
                "Administrator access required."

        });

    }


    next();

}


// ============================================================
// LOGIN
// ============================================================

app.post(
    "/api/auth/login",
    loginLimiter,
    async (req, res) => {

        try {

            const {
                username,
                password
            } = req.body;


            if (!username || !password) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Username and password are required."

                });

            }


            const result =
                await pool.query(

                    `
                    SELECT
                        id,
                        username,
                        full_name,
                        role,
                        password_hash,
                        active

                    FROM staff

                    WHERE LOWER(username)
                        = LOWER($1)

                    LIMIT 1
                    `,

                    [
                        username.trim()
                    ]

                );


            if (result.rows.length === 0) {

                return res.status(401).json({

                    success: false,

                    message:
                        "Invalid username or password."

                });

            }


            const user =
                result.rows[0];


            if (!user.active) {

                return res.status(403).json({

                    success: false,

                    message:
                        "This account has been deactivated."

                });

            }


            const validPassword =
                await bcrypt.compare(

                    password,

                    user.password_hash

                );


            if (!validPassword) {

                return res.status(401).json({

                    success: false,

                    message:
                        "Invalid username or password."

                });

            }


            const token =
                createToken(user);


            res.cookie(
                "scagss_token",
                token,
                {

                    httpOnly: true,

                    secure:
                        process.env.NODE_ENV
                        === "production",

                    sameSite: "lax",

                    maxAge:
                        8 * 60 * 60 * 1000

                }
            );


            res.json({

                success: true,

                message:
                    "Login successful.",

                user: {

                    id: user.id,

                    username:
                        user.username,

                    fullName:
                        user.full_name,

                    role:
                        user.role

                }

            });


        } catch (error) {

            console.error(
                "LOGIN ERROR:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Server error during login."

            });

        }

    }
);


// ============================================================
// LOGOUT
// ============================================================

app.post(
    "/api/auth/logout",
    (req, res) => {

        res.clearCookie(
            "scagss_token"
        );


        res.json({

            success: true,

            message:
                "Logged out successfully."

        });

    }
);


// ============================================================
// CURRENT USER
// ============================================================

app.get(
    "/api/me",
    authenticate,
    async (req, res) => {

        try {

            const result =
                await pool.query(

                    `
                    SELECT
                        id,
                        username,
                        full_name,
                        role,
                        active

                    FROM staff

                    WHERE id = $1

                    LIMIT 1
                    `,

                    [
                        req.user.id
                    ]

                );


            if (result.rows.length === 0) {

                return res.status(404).json({

                    success: false,

                    message:
                        "User account not found."

                });

            }


            const user =
                result.rows[0];


            res.json({

                success: true,

                user: {

                    id: user.id,

                    username:
                        user.username,

                    fullName:
                        user.full_name,

                    role:
                        user.role,

                    active:
                        user.active

                }

            });

        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    "Unable to retrieve account."

            });

        }

    }
);


// ============================================================
// GPS DISTANCE CALCULATION
// ============================================================

function calculateDistance(
    lat1,
    lon1,
    lat2,
    lon2
) {

    const earthRadius =
        6371000;


    const dLat =
        toRadians(
            lat2 - lat1
        );


    const dLon =
        toRadians(
            lon2 - lon1
        );


    const a =

        Math.sin(dLat / 2) ** 2

        +

        Math.cos(
            toRadians(lat1)
        )

        *

        Math.cos(
            toRadians(lat2)
        )

        *

        Math.sin(dLon / 2) ** 2;


    const c =

        2 *

        Math.atan2(

            Math.sqrt(a),

            Math.sqrt(1 - a)

        );


    return earthRadius * c;

}


function toRadians(degrees) {

    return degrees *
        Math.PI /
        180;

}


// ============================================================
// GET GPS SETTINGS
// ============================================================

app.get(
    "/api/settings/gps",
    authenticate,
    async (req, res) => {

        try {

            const result =
                await pool.query(

                    `
                    SELECT
                        latitude,
                        longitude,
                        radius,
                        updated_at

                    FROM school_settings

                    WHERE id = 1

                    LIMIT 1
                    `

                );


            if (result.rows.length === 0) {

                return res.status(404).json({

                    success: false,

                    message:
                        "School GPS settings have not been configured."

                });

            }


            const settings =
                result.rows[0];


            res.json({

                success: true,

                gps: {

                    latitude:
                        Number(
                            settings.latitude
                        ),

                    longitude:
                        Number(
                            settings.longitude
                        ),

                    radius:
                        Number(
                            settings.radius
                        ),

                    updatedAt:
                        settings.updated_at

                }

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    "Unable to retrieve GPS settings."

            });

        }

    }
);


// ============================================================
// UPDATE GPS SETTINGS
// ADMIN ONLY
// ============================================================

app.put(
    "/api/settings/gps",
    authenticate,
    requireAdmin,
    async (req, res) => {

        try {

            const {
                latitude,
                longitude,
                radius
            } = req.body;


            const lat =
                Number(latitude);

            const lon =
                Number(longitude);

            const rad =
                Number(radius);


            if (
                !Number.isFinite(lat) ||
                !Number.isFinite(lon) ||
                !Number.isFinite(rad)
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Invalid GPS values."

                });

            }


            if (
                lat < -90 ||
                lat > 90
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Invalid latitude."

                });

            }


            if (
                lon < -180 ||
                lon > 180
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Invalid longitude."

                });

            }


            if (
                rad < 50 ||
                rad > 5000
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Radius must be between 50 and 5000 metres."

                });

            }


            await pool.query(

                `
                INSERT INTO school_settings
                (
                    id,
                    latitude,
                    longitude,
                    radius,
                    updated_at
                )

                VALUES
                (
                    1,
                    $1,
                    $2,
                    $3,
                    CURRENT_TIMESTAMP
                )

                ON CONFLICT (id)

                DO UPDATE SET

                    latitude =
                        EXCLUDED.latitude,

                    longitude =
                        EXCLUDED.longitude,

                    radius =
                        EXCLUDED.radius,

                    updated_at =
                        CURRENT_TIMESTAMP
                `,

                [
                    lat,
                    lon,
                    rad
                ]

            );


            res.json({

                success: true,

                message:
                    "GPS settings updated successfully."

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    "Unable to update GPS settings."

            });

        }

    }
);


// ============================================================
// CLOCK IN
// ============================================================

app.post(
    "/api/attendance/clock-in",
    authenticate,
    async (req, res) => {

        try {

            const {
                latitude,
                longitude,
                accuracy
            } = req.body;


            const lat =
                Number(latitude);

            const lon =
                Number(longitude);

            const gpsAccuracy =
                Number(accuracy);


            if (
                !Number.isFinite(lat) ||
                !Number.isFinite(lon)
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Valid GPS coordinates are required."

                });

            }


            const settingsResult =
                await pool.query(

                    `
                    SELECT
                        latitude,
                        longitude,
                        radius

                    FROM school_settings

                    WHERE id = 1

                    LIMIT 1
                    `

                );


            if (
                settingsResult.rows.length === 0
            ) {

                return res.status(500).json({

                    success: false,

                    message:
                        "School GPS location has not been configured."

                });

            }


            const settings =
                settingsResult.rows[0];


            const distance =
                calculateDistance(

                    lat,

                    lon,

                    Number(
                        settings.latitude
                    ),

                    Number(
                        settings.longitude
                    )

                );


            const radius =
                Number(
                    settings.radius
                );


            if (
                distance > radius
            ) {

                return res.status(403).json({

                    success: false,

                    message:
                        `Attendance denied. You are approximately ${Math.round(distance)} metres from school.`,

                    distance:
                        Math.round(distance),

                    allowedRadius:
                        radius,

                    gpsVerified:
                        false

                });

            }


            const existing =
                await pool.query(

                    `
                    SELECT
                        id,
                        clock_in,
                        clock_out

                    FROM attendance

                    WHERE staff_id = $1

                    AND attendance_date
                        = CURRENT_DATE

                    LIMIT 1
                    `,

                    [
                        req.user.id
                    ]

                );


            if (
                existing.rows.length > 0
            ) {

                return res.status(409).json({

                    success: false,

                    message:
                        "You have already marked attendance today.",

                    attendance:
                        existing.rows[0]

                });

            }


            const currentHourResult =
                await pool.query(

                    `
                    SELECT
                        EXTRACT(
                            HOUR
                            FROM CURRENT_TIMESTAMP
                        ) AS hour
                    `

                );


            const currentHour =
                Number(
                    currentHourResult
                        .rows[0]
                        .hour
                );


            const status =
                currentHour >= 8
                    ? "LATE"
                    : "PRESENT";


            const result =
                await pool.query(

                    `
                    INSERT INTO attendance
                    (
                        staff_id,

                        attendance_date,

                        clock_in,

                        status,

                        gps_verified,

                        clock_in_latitude,

                        clock_in_longitude,

                        clock_in_accuracy,

                        clock_in_distance
                    )

                    VALUES
                    (
                        $1,

                        CURRENT_DATE,

                        CURRENT_TIMESTAMP,

                        $2,

                        TRUE,

                        $3,

                        $4,

                        $5,

                        $6
                    )

                    RETURNING *
                    `,

                    [

                        req.user.id,

                        status,

                        lat,

                        lon,

                        Number.isFinite(
                            gpsAccuracy
                        )
                            ? gpsAccuracy
                            : null,

                        Math.round(
                            distance
                        )

                    ]

                );


            res.json({

                success: true,

                message:
                    "Attendance marked successfully.",

                attendance:
                    result.rows[0]

            });


        } catch (error) {

            console.error(
                "CLOCK IN ERROR:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Unable to mark attendance."

            });

        }

    }
);


// ============================================================
// CLOCK OUT
// ============================================================

app.post(
    "/api/attendance/clock-out",
    authenticate,
    async (req, res) => {

        try {

            const {
                latitude,
                longitude,
                accuracy
            } = req.body;


            const lat =
                Number(latitude);

            const lon =
                Number(longitude);

            const gpsAccuracy =
                Number(accuracy);


            if (
                !Number.isFinite(lat) ||
                !Number.isFinite(lon)
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Valid GPS coordinates are required."

                });

            }


            const settingsResult =
                await pool.query(

                    `
                    SELECT
                        latitude,
                        longitude,
                        radius

                    FROM school_settings

                    WHERE id = 1

                    LIMIT 1
                    `

                );


            if (
                settingsResult.rows.length === 0
            ) {

                return res.status(500).json({

                    success: false,

                    message:
                        "School GPS location has not been configured."

                });

            }


            const settings =
                settingsResult.rows[0];


            const distance =
                calculateDistance(

                    lat,

                    lon,

                    Number(
                        settings.latitude
                    ),

                    Number(
                        settings.longitude
                    )

                );


            const radius =
                Number(
                    settings.radius
                );


            if (
                distance > radius
            ) {

                return res.status(403).json({

                    success: false,

                    message:
                        `Clock-out denied. You are approximately ${Math.round(distance)} metres from school.`,

                    distance:
                        Math.round(distance),

                    allowedRadius:
                        radius,

                    gpsVerified:
                        false

                });

            }


            const existing =
                await pool.query(

                    `
                    SELECT *

                    FROM attendance

                    WHERE staff_id = $1

                    AND attendance_date
                        = CURRENT_DATE

                    LIMIT 1
                    `,

                    [
                        req.user.id
                    ]

                );


            if (
                existing.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "You have not clocked in today."

                });

            }


            if (
                existing.rows[0].clock_out
            ) {

                return res.status(409).json({

                    success: false,

                    message:
                        "You have already clocked out today."

                });

            }


            const result =
                await pool.query(

                    `
                    UPDATE attendance

                    SET

                        clock_out =
                            CURRENT_TIMESTAMP,

                        clock_out_latitude =
                            $1,

                        clock_out_longitude =
                            $2,

                        clock_out_accuracy =
                            $3,

                        clock_out_distance =
                            $4

                    WHERE id = $5

                    RETURNING *
                    `,

                    [

                        lat,

                        lon,

                        Number.isFinite(
                            gpsAccuracy
                        )
                            ? gpsAccuracy
                            : null,

                        Math.round(
                            distance
                        ),

                        existing.rows[0].id

                    ]

                );


            res.json({

                success: true,

                message:
                    "Clock-out recorded successfully.",

                attendance:
                    result.rows[0]

            });


        } catch (error) {

            console.error(
                "CLOCK OUT ERROR:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Unable to record clock-out."

            });

        }

    }
);


// ============================================================
// TEACHER ATTENDANCE HISTORY
// ============================================================

app.get(
    "/api/attendance/history",
    authenticate,
    async (req, res) => {

        try {

            const result =
                await pool.query(

                    `
                    SELECT

                        id,

                        attendance_date,

                        clock_in,

                        clock_out,

                        status,

                        gps_verified,

                        clock_in_latitude,

                        clock_in_longitude,

                        clock_in_accuracy,

                        clock_in_distance,

                        clock_out_latitude,

                        clock_out_longitude,

                        clock_out_accuracy,

                        clock_out_distance

                    FROM attendance

                    WHERE staff_id = $1

                    ORDER BY
                        attendance_date DESC

                    LIMIT 100
                    `,

                    [
                        req.user.id
                    ]

                );


            res.json({

                success: true,

                attendance:
                    result.rows

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    "Unable to retrieve attendance history."

            });

        }

    }
);


// ============================================================
// ADMIN — STAFF LIST
// ============================================================

app.get(
    "/api/admin/staff",
    authenticate,
    requireAdmin,
    async (req, res) => {

        try {

            const result =
                await pool.query(

                    `
                    SELECT

                        id,

                        username,

                        full_name,

                        role,

                        active,

                        created_at

                    FROM staff

                    ORDER BY
                        full_name ASC
                    `

                );


            res.json({

                success: true,

                staff:
                    result.rows

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    "Unable to retrieve staff."

            });

        }

    }
);


// ============================================================
// ADMIN — ADD STAFF
// ============================================================

app.post(
    "/api/admin/staff",
    authenticate,
    requireAdmin,
    async (req, res) => {

        try {

            const {
                username,
                password,
                fullName,
                role
            } = req.body;


            if (
                !username ||
                !password ||
                !fullName
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Username, password and full name are required."

                });

            }


            if (
                password.length < 8
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Password must contain at least 8 characters."

                });

            }


            const passwordHash =
                await bcrypt.hash(
                    password,
                    12
                );


            const safeRole =
                role === "admin"
                    ? "admin"
                    : "teacher";


            const result =
                await pool.query(

                    `
                    INSERT INTO staff
                    (
                        username,

                        password_hash,

                        full_name,

                        role,

                        active
                    )

                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        $4,
                        TRUE
                    )

                    RETURNING

                        id,

                        username,

                        full_name,

                        role,

                        active
                    `,

                    [

                        username.trim(),

                        passwordHash,

                        fullName.trim(),

                        safeRole

                    ]

                );


            res.status(201).json({

                success: true,

                message:
                    "Staff member added successfully.",

                staff:
                    result.rows[0]

            });


        } catch (error) {

            console.error(error);


            if (
                error.code === "23505"
            ) {

                return res.status(409).json({

                    success: false,

                    message:
                        "That username already exists."

                });

            }


            res.status(500).json({

                success: false,

                message:
                    "Unable to create staff account."

            });

        }

    }
);


// ============================================================
// ADMIN — ACTIVATE / DEACTIVATE STAFF
// ============================================================

app.patch(
    "/api/admin/staff/:id/status",
    authenticate,
    requireAdmin,
    async (req, res) => {

        try {

            const id =
                Number(
                    req.params.id
                );

            const {
                active
            } = req.body;


            if (
                !Number.isInteger(id)
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Invalid staff ID."

                });

            }


            const result =
                await pool.query(

                    `
                    UPDATE staff

                    SET
                        active = $1

                    WHERE id = $2

                    RETURNING

                        id,

                        username,

                        full_name,

                        role,

                        active
                    `,

                    [
                        Boolean(active),

                        id
                    ]

                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Staff member not found."

                });

            }


            res.json({

                success: true,

                message:
                    "Staff status updated.",

                staff:
                    result.rows[0]

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    "Unable to update staff status."

            });

        }

    }
);


// ============================================================
// ADMIN — COMPLETE ATTENDANCE + GPS MONITOR
// ============================================================

app.get(
    "/api/admin/attendance",
    authenticate,
    requireAdmin,
    async (req, res) => {

        try {

            const result =
                await pool.query(

                    `
                    SELECT

                        a.id,

                        a.attendance_date,

                        a.clock_in,

                        a.clock_out,

                        a.status,

                        a.gps_verified,


                        -- ==================================
                        -- CLOCK-IN GPS
                        -- ==================================

                        a.clock_in_latitude,

                        a.clock_in_longitude,

                        a.clock_in_accuracy,

                        a.clock_in_distance,


                        -- ==================================
                        -- CLOCK-OUT GPS
                        -- ==================================

                        a.clock_out_latitude,

                        a.clock_out_longitude,

                        a.clock_out_accuracy,

                        a.clock_out_distance,


                        -- ==================================
                        -- STAFF
                        -- ==================================

                        s.id AS staff_id,

                        s.username,

                        s.full_name

                    FROM attendance a

                    INNER JOIN staff s

                        ON s.id =
                           a.staff_id

                    ORDER BY

                        a.attendance_date DESC,

                        a.clock_in DESC

                    LIMIT 5000
                    `

                );


            res.json({

                success: true,

                attendance:
                    result.rows

            });


        } catch (error) {

            console.error(
                "ADMIN ATTENDANCE ERROR:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Unable to retrieve attendance report."

            });

        }

    }
);


// ============================================================
// ADMIN — TODAY'S ATTENDANCE
// ============================================================

app.get(
    "/api/admin/attendance/today",
    authenticate,
    requireAdmin,
    async (req, res) => {

        try {

            const result =
                await pool.query(

                    `
                    SELECT

                        a.id,

                        a.attendance_date,

                        a.clock_in,

                        a.clock_out,

                        a.status,

                        a.gps_verified,


                        -- CLOCK-IN GPS

                        a.clock_in_latitude,

                        a.clock_in_longitude,

                        a.clock_in_accuracy,

                        a.clock_in_distance,


                        -- CLOCK-OUT GPS

                        a.clock_out_latitude,

                        a.clock_out_longitude,

                        a.clock_out_accuracy,

                        a.clock_out_distance,


                        s.username,

                        s.full_name

                    FROM attendance a

                    INNER JOIN staff s

                        ON s.id =
                           a.staff_id

                    WHERE
                        a.attendance_date
                        = CURRENT_DATE

                    ORDER BY
                        a.clock_in ASC
                    `

                );


            res.json({

                success: true,

                date:
                    new Date()
                        .toISOString()
                        .split("T")[0],

                attendance:
                    result.rows

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    "Unable to retrieve today's attendance."

            });

        }

    }
);


// ============================================================
// ADMIN — ATTENDANCE SUMMARY
// ============================================================

app.get(
    "/api/admin/attendance/summary",
    authenticate,
    requireAdmin,
    async (req, res) => {

        try {

            const result =
                await pool.query(

                    `
                    SELECT

                        COUNT(*) AS total_records,

                        COUNT(
                            CASE
                                WHEN status =
                                    'PRESENT'
                                THEN 1
                            END
                        ) AS present,

                        COUNT(
                            CASE
                                WHEN status =
                                    'LATE'
                                THEN 1
                            END
                        ) AS late,

                        COUNT(
                            CASE
                                WHEN clock_out
                                    IS NOT NULL
                                THEN 1
                            END
                        ) AS clocked_out,

                        COUNT(
                            CASE
                                WHEN gps_verified =
                                    TRUE
                                THEN 1
                            END
                        ) AS gps_verified

                    FROM attendance

                    WHERE
                        attendance_date =
                        CURRENT_DATE
                    `

                );


            res.json({

                success: true,

                summary:
                    result.rows[0]

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    "Unable to retrieve attendance summary."

            });

        }

    }
);


// ============================================================
// ADMIN — GET ONE ATTENDANCE GPS RECORD
// ============================================================

app.get(
    "/api/admin/attendance/:id",
    authenticate,
    requireAdmin,
    async (req, res) => {

        try {

            const id =
                Number(
                    req.params.id
                );


            if (
                !Number.isInteger(id)
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Invalid attendance ID."

                });

            }


            const result =
                await pool.query(

                    `
                    SELECT

                        a.id,

                        a.attendance_date,

                        a.clock_in,

                        a.clock_out,

                        a.status,

                        a.gps_verified,


                        -- CLOCK-IN

                        a.clock_in_latitude,

                        a.clock_in_longitude,

                        a.clock_in_accuracy,

                        a.clock_in_distance,


                        -- CLOCK-OUT

                        a.clock_out_latitude,

                        a.clock_out_longitude,

                        a.clock_out_accuracy,

                        a.clock_out_distance,


                        -- STAFF

                        s.id AS staff_id,

                        s.username,

                        s.full_name

                    FROM attendance a

                    INNER JOIN staff s

                        ON s.id =
                           a.staff_id

                    WHERE
                        a.id = $1

                    LIMIT 1
                    `,

                    [
                        id
                    ]

                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Attendance record not found."

                });

            }


            res.json({

                success: true,

                attendance:
                    result.rows[0]

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    "Unable to retrieve attendance record."

            });

        }

    }
);


// ============================================================
// ADMIN — GPS RECORDS ONLY
// ============================================================

app.get(
    "/api/admin/gps",
    authenticate,
    requireAdmin,
    async (req, res) => {

        try {

            const result =
                await pool.query(

                    `
                    SELECT

                        a.id,

                        a.attendance_date,

                        s.full_name,

                        s.username,


                        -- CLOCK-IN

                        a.clock_in,

                        a.clock_in_latitude,

                        a.clock_in_longitude,

                        a.clock_in_accuracy,

                        a.clock_in_distance,


                        -- CLOCK-OUT

                        a.clock_out,

                        a.clock_out_latitude,

                        a.clock_out_longitude,

                        a.clock_out_accuracy,

                        a.clock_out_distance,


                        a.gps_verified

                    FROM attendance a

                    INNER JOIN staff s

                        ON s.id =
                           a.staff_id

                    ORDER BY

                        a.attendance_date DESC,

                        a.clock_in DESC

                    LIMIT 5000
                    `

                );


            res.json({

                success: true,

                gps:
                    result.rows

            });


        } catch (error) {

            console.error(
                "ADMIN GPS ERROR:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Unable to retrieve GPS records."

            });

        }

    }
);


// ============================================================
// ADMIN — GPS RECORD FOR TODAY
// ============================================================

app.get(
    "/api/admin/gps/today",
    authenticate,
    requireAdmin,
    async (req, res) => {

        try {

            const result =
                await pool.query(

                    `
                    SELECT

                        a.id,

                        a.attendance_date,

                        s.full_name,

                        s.username,


                        -- CLOCK-IN

                        a.clock_in,

                        a.clock_in_latitude,

                        a.clock_in_longitude,

                        a.clock_in_accuracy,

                        a.clock_in_distance,


                        -- CLOCK-OUT

                        a.clock_out,

                        a.clock_out_latitude,

                        a.clock_out_longitude,

                        a.clock_out_accuracy,

                        a.clock_out_distance,


                        a.gps_verified

                    FROM attendance a

                    INNER JOIN staff s

                        ON s.id =
                           a.staff_id

                    WHERE
                        a.attendance_date =
                        CURRENT_DATE

                    ORDER BY
                        a.clock_in ASC
                    `

                );


            res.json({

                success: true,

                gps:
                    result.rows

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    "Unable to retrieve today's GPS records."

            });

        }

    }
);


// ============================================================
// ADMIN — EXPORT-READY ATTENDANCE DATA
// ============================================================

app.get(
    "/api/admin/reports/attendance",
    authenticate,
    requireAdmin,
    async (req, res) => {

        try {

            const result =
                await pool.query(

                    `
                    SELECT

                        s.full_name,

                        s.username,

                        a.attendance_date,

                        a.clock_in,

                        a.clock_out,

                        a.status,

                        a.gps_verified,


                        a.clock_in_latitude,

                        a.clock_in_longitude,

                        a.clock_in_accuracy,

                        a.clock_in_distance,


                        a.clock_out_latitude,

                        a.clock_out_longitude,

                        a.clock_out_accuracy,

                        a.clock_out_distance

                    FROM attendance a

                    INNER JOIN staff s

                        ON s.id =
                           a.staff_id

                    ORDER BY

                        a.attendance_date DESC,

                        s.full_name ASC
                    `

                );


            res.json({

                success: true,

                records:
                    result.rows

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    "Unable to generate attendance report."

            });

        }

    }
);


// ============================================================
// 404 API HANDLER
// ============================================================

app.use(
    "/api",
    (req, res) => {

        res.status(404).json({

            success: false,

            message:
                "API endpoint not found."

        });

    }
);


// ============================================================
// GLOBAL ERROR HANDLER
// ============================================================

app.use(
    (error, req, res, next) => {

        console.error(
            "SERVER ERROR:",
            error
        );


        res.status(500).json({

            success: false,

            message:
                "Internal server error."

        });

    }
);


// ============================================================
// START SERVER
// ============================================================

app.listen(
    PORT,
    () => {

        console.log("");
        console.log(
            "=============================================="
        );

        console.log(
            "     S.C.A.G.S.S STAFF PORTAL V1"
        );

        console.log(
            "=============================================="
        );

        console.log(
            `Server running on port ${PORT}`
        );

        console.log(
            "Database: PostgreSQL"
        );

        console.log(
            "GPS verification: ENABLED"
        );

        console.log(
            "GPS records visible to Admin: ENABLED"
        );

        console.log(
            "Clock-in GPS: ENABLED"
        );

        console.log(
            "Clock-out GPS: ENABLED"
        );

        console.log(
            "=============================================="
        );

        console.log("");

    }
);
