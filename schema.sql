-- ============================================================
-- S.C.A.G.S.S STAFF PORTAL V1
-- PostgreSQL DATABASE SCHEMA
-- ============================================================

-- ============================================================
-- STAFF TABLE
-- ============================================================

CREATE TABLE IF NOT EXISTS staff (

    id SERIAL PRIMARY KEY,

    username VARCHAR(50) NOT NULL UNIQUE,

    password_hash TEXT NOT NULL,

    full_name VARCHAR(150) NOT NULL,

    role VARCHAR(20) NOT NULL DEFAULT 'teacher',

    active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT staff_role_check
        CHECK (
            role IN ('teacher', 'admin')
        )

);


-- ============================================================
-- ATTENDANCE TABLE
-- ============================================================

CREATE TABLE IF NOT EXISTS attendance (

    id BIGSERIAL PRIMARY KEY,

    staff_id INTEGER NOT NULL,

    attendance_date DATE NOT NULL,

    clock_in TIMESTAMP WITH TIME ZONE,

    clock_out TIMESTAMP WITH TIME ZONE,

    status VARCHAR(20) NOT NULL DEFAULT 'PRESENT',

    gps_verified BOOLEAN NOT NULL DEFAULT FALSE,


    -- ========================================================
    -- CLOCK-IN GPS
    -- ========================================================

    clock_in_latitude DOUBLE PRECISION,

    clock_in_longitude DOUBLE PRECISION,

    clock_in_accuracy DOUBLE PRECISION,

    clock_in_distance DOUBLE PRECISION,


    -- ========================================================
    -- CLOCK-OUT GPS
    -- ========================================================

    clock_out_latitude DOUBLE PRECISION,

    clock_out_longitude DOUBLE PRECISION,

    clock_out_accuracy DOUBLE PRECISION,

    clock_out_distance DOUBLE PRECISION,


    created_at TIMESTAMP WITH TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,


    -- ========================================================
    -- FOREIGN KEY
    -- ========================================================

    CONSTRAINT attendance_staff_fk

        FOREIGN KEY (staff_id)

        REFERENCES staff(id)

        ON DELETE CASCADE,


    -- ========================================================
    -- ATTENDANCE STATUS
    -- ========================================================

    CONSTRAINT attendance_status_check

        CHECK (
            status IN (
                'PRESENT',
                'LATE',
                'ABSENT'
            )
        ),


    -- ========================================================
    -- ONE RECORD PER STAFF MEMBER PER DAY
    -- ========================================================

    CONSTRAINT unique_staff_attendance_day

        UNIQUE (
            staff_id,
            attendance_date
        )

);


-- ============================================================
-- SCHOOL GPS SETTINGS
-- ============================================================

CREATE TABLE IF NOT EXISTS school_settings (

    id INTEGER PRIMARY KEY,

    latitude DOUBLE PRECISION NOT NULL,

    longitude DOUBLE PRECISION NOT NULL,

    radius DOUBLE PRECISION NOT NULL DEFAULT 500,

    updated_at TIMESTAMP WITH TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,


    -- Latitude must be valid

    CONSTRAINT school_latitude_check

        CHECK (
            latitude >= -90
            AND latitude <= 90
        ),


    -- Longitude must be valid

    CONSTRAINT school_longitude_check

        CHECK (
            longitude >= -180
            AND longitude <= 180
        ),


    -- Radius must be positive

    CONSTRAINT school_radius_check

        CHECK (
            radius > 0
        )

);


-- ============================================================
-- DEFAULT SCHOOL GPS CONFIGURATION
-- ============================================================

-- IMPORTANT:
--
-- These are temporary placeholder coordinates.
--
-- BEFORE OFFICIAL USE:
-- Replace 0.000000 / 0.000000 with the actual
-- coordinates of Senior Chief Adano Girls Senior School.
--
-- The administrator can later update the GPS settings
-- through the Admin Portal.

INSERT INTO school_settings
(
    id,
    latitude,
    longitude,
    radius
)

VALUES
(
    1,
    0.000000,
    0.000000,
    500
)

ON CONFLICT (id)

DO NOTHING;


-- ============================================================
-- INDEXES
-- ============================================================

CREATE INDEX IF NOT EXISTS
idx_attendance_staff

ON attendance(staff_id);


CREATE INDEX IF NOT EXISTS
idx_attendance_date

ON attendance(attendance_date);


CREATE INDEX IF NOT EXISTS
idx_attendance_staff_date

ON attendance(
    staff_id,
    attendance_date
);


CREATE INDEX IF NOT EXISTS
idx_staff_username

ON staff(username);


-- ============================================================
-- DATABASE READY
-- ============================================================

SELECT
    'S.C.A.G.S.S STAFF PORTAL database ready.'
    AS message;
