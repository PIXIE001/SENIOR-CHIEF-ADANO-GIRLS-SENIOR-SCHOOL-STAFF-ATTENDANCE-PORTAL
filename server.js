require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");

const app = express();

app.use(helmet());
app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: process.env.FRONTEND_URL || true,
    credentials: true
  })
);

const PORT = process.env.PORT || 3000;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !JWT_SECRET) {
  console.error("Missing required environment variables.");
  process.exit(1);
}

/* =========================================================
   SUPABASE REQUEST HELPER
========================================================= */

async function supabaseRequest(path, options = {}) {
  const response = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    ...options,
    headers: {
      apikey: SUPABASE_ANON_KEY,
      Authorization: `Bearer ${SUPABASE_ANON_KEY}`,
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  const text = await response.text();

  let data = null;

  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }

  if (!response.ok) {
    const message =
      data?.message ||
      data?.hint ||
      data?.error_description ||
      "Supabase request failed";

    const error = new Error(message);
    error.status = response.status;
    error.details = data;
    throw error;
  }

  return data;
}

/* =========================================================
   JWT
========================================================= */

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username,
      role: user.role,
      full_name: user.full_name
    },
    JWT_SECRET,
    {
      expiresIn: "12h"
    }
  );
}

function getToken(req) {
  const auth = req.headers.authorization;

  if (auth && auth.startsWith("Bearer ")) {
    return auth.substring(7);
  }

  return req.cookies.scagss_token || null;
}

function requireAuth(req, res, next) {
  try {
    const token = getToken(req);

    if (!token) {
      return res.status(401).json({
        error: "Authentication required"
      });
    }

    req.user = jwt.verify(token, JWT_SECRET);

    next();
  } catch {
    return res.status(401).json({
      error: "Invalid or expired session"
    });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({
      error: "Administrator access required"
    });
  }

  next();
}

/* =========================================================
   GPS
========================================================= */

function isValidCoordinate(lat, lon) {
  return (
    Number.isFinite(lat) &&
    Number.isFinite(lon) &&
    lat >= -90 &&
    lat <= 90 &&
    lon >= -180 &&
    lon <= 180
  );
}

function distanceInMeters(lat1, lon1, lat2, lon2) {
  const R = 6371000;

  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;

  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) ** 2;

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  return R * c;
}

function kenyaToday() {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "Africa/Nairobi",
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).format(new Date());
}

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    portal: "S.C.A.G.S.S STAFF PORTAL",
    database: "Supabase"
  });
});

/* =========================================================
   LOGIN
========================================================= */

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false
});

app.post("/api/auth/login", loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        error: "Username and password are required"
      });
    }

    const staff = await supabaseRequest(
      `staff?username=eq.${encodeURIComponent(
        username
      )}&select=id,username,password_hash,full_name,role,active&limit=1`,
      {
        method: "GET"
      }
    );

    if (!staff || staff.length === 0) {
      return res.status(401).json({
        error: "Invalid username or password"
      });
    }

    const user = staff[0];

    if (!user.active) {
      return res.status(403).json({
        error: "This account is inactive"
      });
    }

    const passwordMatches = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordMatches) {
      return res.status(401).json({
        error: "Invalid username or password"
      });
    }

    const token = createToken(user);

    res.cookie("scagss_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 12 * 60 * 60 * 1000
    });

    res.json({
      message: "Login successful",
      user: {
        id: user.id,
        username: user.username,
        full_name: user.full_name,
        role: user.role
      }
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Login failed"
    });
  }
});

/* =========================================================
   LOGOUT
========================================================= */

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("scagss_token");

  res.json({
    message: "Logged out successfully"
  });
});

/* =========================================================
   CURRENT USER
========================================================= */

app.get("/api/me", requireAuth, (req, res) => {
  res.json({
    user: req.user
  });
});

/* =========================================================
   GPS SETTINGS
========================================================= */

app.get("/api/settings/gps", requireAuth, async (req, res) => {
  try {
    const settings = await supabaseRequest(
      "school_settings?id=eq.1&select=id,latitude,longitude,radius&limit=1"
    );

    if (!settings.length) {
      return res.status(404).json({
        error: "GPS settings not found"
      });
    }

    res.json({
      settings: settings[0]
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to load GPS settings"
    });
  }
});

app.put(
  "/api/settings/gps",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const latitude = Number(req.body.latitude);
      const longitude = Number(req.body.longitude);
      const radius = Number(req.body.radius);

      if (!isValidCoordinate(latitude, longitude)) {
        return res.status(400).json({
          error: "Invalid GPS coordinates"
        });
      }

      if (!Number.isFinite(radius) || radius < 50 || radius > 5000) {
        return res.status(400).json({
          error: "Radius must be between 50 and 5000 metres"
        });
      }

      const updated = await supabaseRequest("school_settings?id=eq.1", {
        method: "PATCH",
        headers: {
          Prefer: "return=representation"
        },
        body: JSON.stringify({
          latitude,
          longitude,
          radius,
          updated_at: new Date().toISOString()
        })
      });

      res.json({
        message: "GPS settings updated",
        settings: updated[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to update GPS settings"
      });
    }
  }
);

/* =========================================================
   GET SCHOOL SETTINGS
========================================================= */

async function getSchoolSettings() {
  const settings = await supabaseRequest(
    "school_settings?id=eq.1&select=latitude,longitude,radius&limit=1"
  );

  if (!settings.length) {
    throw new Error("School GPS settings not configured");
  }

  return settings[0];
}

/* =========================================================
   CLOCK IN
========================================================= */

app.post(
  "/api/attendance/clock-in",
  requireAuth,
  async (req, res) => {
    try {
      const lat = Number(req.body.lat);
      const lon = Number(req.body.lon);
      const accuracy = Number(req.body.accuracy);

      if (!isValidCoordinate(lat, lon)) {
        return res.status(400).json({
          error: "Invalid GPS coordinates"
        });
      }

      if (
        !Number.isFinite(accuracy) ||
        accuracy < 0 ||
        accuracy > 500
      ) {
        return res.status(400).json({
          error: "GPS accuracy is too poor"
        });
      }

      const settings = await getSchoolSettings();

      if (
        Number(settings.latitude) === 0 &&
        Number(settings.longitude) === 0
      ) {
        return res.status(400).json({
          error: "School GPS location has not been configured"
        });
      }

      const distance = distanceInMeters(
        lat,
        lon,
        Number(settings.latitude),
        Number(settings.longitude)
      );

      const radius = Number(settings.radius);

      if (distance > radius) {
        return res.status(403).json({
          error: `You are outside the school attendance area. Distance: ${Math.round(
            distance
          )} metres. Allowed: ${radius} metres.`,
          distance,
          radius
        });
      }

      const today = kenyaToday();

      const existing = await supabaseRequest(
        `attendance?staff_id=eq.${req.user.id}&attendance_date=eq.${today}&select=id,clock_in,clock_out,status&limit=1`
      );

      if (existing.length && existing[0].clock_in) {
        return res.status(409).json({
          error: "You have already clocked in today"
        });
      }

      const now = new Date();

      const kenyaTime = new Intl.DateTimeFormat("en-GB", {
        timeZone: "Africa/Nairobi",
        hour: "2-digit",
        minute: "2-digit",
        hour12: false
      }).format(now);

      const [hour, minute] = kenyaTime.split(":").map(Number);

      const status =
        hour > 8 || (hour === 8 && minute > 0)
          ? "LATE"
          : "PRESENT";

      const record = {
        staff_id: req.user.id,
        attendance_date: today,
        clock_in: now.toISOString(),
        status,
        gps_verified: true,
        clock_in_lat: lat,
        clock_in_lon: lon,
        clock_in_accuracy: accuracy,
        clock_in_distance: Math.round(distance)
      };

      let result;

      if (existing.length) {
        result = await supabaseRequest(
          `attendance?id=eq.${existing[0].id}`,
          {
            method: "PATCH",
            headers: {
              Prefer: "return=representation"
            },
            body: JSON.stringify(record)
          }
        );
      } else {
        result = await supabaseRequest("attendance", {
          method: "POST",
          headers: {
            Prefer: "return=representation"
          },
          body: JSON.stringify(record)
        });
      }

      res.json({
        message: "Clock-in successful",
        attendance: result[0],
        gps: {
          latitude: lat,
          longitude: lon,
          accuracy,
          distance: Math.round(distance),
          verified: true
        }
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Clock-in failed"
      });
    }
  }
);

/* =========================================================
   CLOCK OUT
========================================================= */

app.post(
  "/api/attendance/clock-out",
  requireAuth,
  async (req, res) => {
    try {
      const lat = Number(req.body.lat);
      const lon = Number(req.body.lon);
      const accuracy = Number(req.body.accuracy);

      if (!isValidCoordinate(lat, lon)) {
        return res.status(400).json({
          error: "Invalid GPS coordinates"
        });
      }

      if (
        !Number.isFinite(accuracy) ||
        accuracy < 0 ||
        accuracy > 500
      ) {
        return res.status(400).json({
          error: "GPS accuracy is too poor"
        });
      }

      const settings = await getSchoolSettings();

      if (
        Number(settings.latitude) === 0 &&
        Number(settings.longitude) === 0
      ) {
        return res.status(400).json({
          error: "School GPS location has not been configured"
        });
      }

      const distance = distanceInMeters(
        lat,
        lon,
        Number(settings.latitude),
        Number(settings.longitude)
      );

      const radius = Number(settings.radius);

      if (distance > radius) {
        return res.status(403).json({
          error: `You are outside the school attendance area. Distance: ${Math.round(
            distance
          )} metres. Allowed: ${radius} metres.`,
          distance,
          radius
        });
      }

      const today = kenyaToday();

      const existing = await supabaseRequest(
        `attendance?staff_id=eq.${req.user.id}&attendance_date=eq.${today}&select=*&limit=1`
      );

      if (!existing.length || !existing[0].clock_in) {
        return res.status(400).json({
          error: "You have not clocked in today"
        });
      }

      if (existing[0].clock_out) {
        return res.status(409).json({
          error: "You have already clocked out today"
        });
      }

      const result = await supabaseRequest(
        `attendance?id=eq.${existing[0].id}`,
        {
          method: "PATCH",
          headers: {
            Prefer: "return=representation"
          },
          body: JSON.stringify({
            clock_out: new Date().toISOString(),
            clock_out_lat: lat,
            clock_out_lon: lon,
            clock_out_accuracy: accuracy,
            clock_out_distance: Math.round(distance),
            gps_verified: true
          })
        }
      );

      res.json({
        message: "Clock-out successful",
        attendance: result[0],
        gps: {
          latitude: lat,
          longitude: lon,
          accuracy,
          distance: Math.round(distance),
          verified: true
        }
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Clock-out failed"
      });
    }
  }
);

/* =========================================================
   STAFF ATTENDANCE HISTORY
========================================================= */

app.get(
  "/api/attendance/history",
  requireAuth,
  async (req, res) => {
    try {
      const records = await supabaseRequest(
        `attendance?staff_id=eq.${req.user.id}&select=*&order=attendance_date.desc&limit=100`
      );

      res.json({
        attendance: records
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to load attendance history"
      });
    }
  }
);

/* =========================================================
   ADMIN — STAFF
========================================================= */

app.get(
  "/api/admin/staff",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const staff = await supabaseRequest(
        "staff?select=id,username,full_name,role,active,created_at&order=full_name.asc"
      );

      res.json({
        staff
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to load staff"
      });
    }
  }
);

/* =========================================================
   ADMIN — CREATE STAFF
========================================================= */

app.post(
  "/api/admin/staff",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const {
        username,
        password,
        full_name,
        role = "teacher"
      } = req.body;

      if (!username || !password || !full_name) {
        return res.status(400).json({
          error: "Username, password and full name are required"
        });
      }

      if (!["teacher", "admin"].includes(role)) {
        return res.status(400).json({
          error: "Invalid role"
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          error: "Password must be at least 8 characters"
        });
      }

      const passwordHash = await bcrypt.hash(password, 12);

      const result = await supabaseRequest("staff", {
        method: "POST",
        headers: {
          Prefer: "return=representation"
        },
        body: JSON.stringify({
          username,
          password_hash: passwordHash,
          full_name,
          role,
          active: true
        })
      });

      res.status(201).json({
        message: "Staff member created",
        staff: result[0]
      });
    } catch (error) {
      console.error(error);

      if (error.status === 409) {
        return res.status(409).json({
          error: "Username already exists"
        });
      }

      res.status(500).json({
        error: "Unable to create staff member"
      });
    }
  }
);

/* =========================================================
   ADMIN — ACTIVATE / DEACTIVATE STAFF
========================================================= */

app.patch(
  "/api/admin/staff/:id/status",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      if (!Number.isInteger(id)) {
        return res.status(400).json({
          error: "Invalid staff ID"
        });
      }

      const active = Boolean(req.body.active);

      const result = await supabaseRequest(
        `staff?id=eq.${id}`,
        {
          method: "PATCH",
          headers: {
            Prefer: "return=representation"
          },
          body: JSON.stringify({
            active
          })
        }
      );

      if (!result.length) {
        return res.status(404).json({
          error: "Staff member not found"
        });
      }

      res.json({
        message: active
          ? "Staff account activated"
          : "Staff account deactivated",
        staff: result[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to update staff status"
      });
    }
  }
);

/* =========================================================
   ADMIN — ATTENDANCE
========================================================= */

app.get(
  "/api/admin/attendance",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const attendance = await supabaseRequest(
        "attendance?select=*,staff(id,username,full_name,role)&order=attendance_date.desc,clock_in.desc&limit=1000"
      );

      res.json({
        attendance
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to load attendance"
      });
    }
  }
);

/* =========================================================
   ADMIN — TODAY ATTENDANCE
========================================================= */

app.get(
  "/api/admin/attendance/today",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const today = kenyaToday();

      const attendance = await supabaseRequest(
        `attendance?attendance_date=eq.${today}&select=*,staff(id,username,full_name,role)&order=clock_in.asc`
      );

      res.json({
        date: today,
        attendance
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to load today's attendance"
      });
    }
  }
);

/* =========================================================
   ADMIN — SUMMARY
========================================================= */

app.get(
  "/api/admin/attendance/summary",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const today = kenyaToday();

      const [staff, attendance] = await Promise.all([
        supabaseRequest(
          "staff?active=eq.true&select=id,role"
        ),
        supabaseRequest(
          `attendance?attendance_date=eq.${today}&select=id,status,clock_in,clock_out`
        )
      ]);

      const teachers = staff.filter(
        (person) => person.role === "teacher"
      ).length;

      const present = attendance.filter(
        (row) => row.clock_in
      ).length;

      const clockedOut = attendance.filter(
        (row) => row.clock_out
      ).length;

      const late = attendance.filter(
        (row) => row.status === "LATE"
      ).length;

      res.json({
        date: today,
        totalTeachers: teachers,
        present,
        clockedOut,
        late,
        absent: Math.max(teachers - present, 0)
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to load attendance summary"
      });
    }
  }
);

/* =========================================================
   ADMIN — GPS
========================================================= */

app.get(
  "/api/admin/gps",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const gps = await supabaseRequest(
        "attendance?select=id,staff_id,attendance_date,clock_in,clock_out,clock_in_lat,clock_in_lon,clock_in_accuracy,clock_in_distance,clock_out_lat,clock_out_lon,clock_out_accuracy,clock_out_distance,gps_verified,staff(id,username,full_name)&order=attendance_date.desc,clock_in.desc&limit=1000"
      );

      res.json({
        gps
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to load GPS records"
      });
    }
  }
);

/* =========================================================
   ADMIN — TODAY GPS
========================================================= */

app.get(
  "/api/admin/gps/today",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const today = kenyaToday();

      const gps = await supabaseRequest(
        `attendance?attendance_date=eq.${today}&select=id,staff_id,attendance_date,clock_in,clock_out,clock_in_lat,clock_in_lon,clock_in_accuracy,clock_in_distance,clock_out_lat,clock_out_lon,clock_out_accuracy,clock_out_distance,gps_verified,staff(id,username,full_name)&order=clock_in.asc`
      );

      res.json({
        date: today,
        gps
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to load today's GPS records"
      });
    }
  }
);

/* =========================================================
   ADMIN — SINGLE ATTENDANCE RECORD
========================================================= */

app.get(
  "/api/admin/attendance/:id",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      const records = await supabaseRequest(
        `attendance?id=eq.${id}&select=*,staff(id,username,full_name,role)&limit=1`
      );

      if (!records.length) {
        return res.status(404).json({
          error: "Attendance record not found"
        });
      }

      res.json({
        attendance: records[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to load attendance record"
      });
    }
  }
);

/* =========================================================
   ADMIN REPORT
========================================================= */

app.get(
  "/api/admin/reports/attendance",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const attendance = await supabaseRequest(
        "attendance?select=*,staff(id,username,full_name,role)&order=attendance_date.desc&limit=5000"
      );

      res.json({
        attendance
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to generate attendance report"
      });
    }
  }
);

/* =========================================================
   404
========================================================= */

app.use("/api/*", (req, res) => {
  res.status(404).json({
    error: "API endpoint not found"
  });
});

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use((error, req, res, next) => {
  console.error(error);

  res.status(500).json({
    error: "Internal server error"
  });
});

/* =========================================================
   START SERVER
========================================================= */

app.listen(PORT, () => {
  console.log("==============================================");
  console.log(" S.C.A.G.S.S STAFF PORTAL");
  console.log("==============================================");
  console.log(` Server running on port ${PORT}`);
  console.log(" Database: Supabase");
  console.log(" GPS verification: ENABLED");
  console.log("==============================================");
});
