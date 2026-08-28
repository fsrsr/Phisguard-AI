package com.phishguard.ai.data.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/**
 * Room Database untuk menyimpan data phishing secara lokal.
 *
 * 3 tabel sesuai diagram arsitektur AI:
 * - PhishingUrl: Database URL yang diketahui phishing
 * - PhishingNumber: Database nomor telepon penipu
 * - OfficialUrl: Database domain resmi (whitelist)
 */
@Database(
    entities = [PhishingUrl::class, PhishingNumber::class, OfficialUrl::class,
        ThreatLocation::class],
    version = 3,
    exportSchema = false
)
abstract class PhishingDatabase : RoomDatabase() {

    abstract fun phishingUrlDao(): PhishingUrlDao
    abstract fun phishingNumberDao(): PhishingNumberDao
    abstract fun officialUrlDao(): OfficialUrlDao
    abstract fun threatLocationDao(): ThreatLocationDao

    companion object {
        private val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // v2 menambahkan kolom pada tabel yang sudah ada.
                // Seluruh ALTER bersifat idempotent (Room hanya menjalankan
                // migration sekali per versi), jadi data user AMAN — tidak
                // ada DROP TABLE seperti fallbackToDestructiveMigration.
                db.execSQL("ALTER TABLE phishing_urls ADD COLUMN isCommunityReported INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE official_urls ADD COLUMN organization TEXT NOT NULL DEFAULT ''")
                db.execSQL("ALTER TABLE official_urls ADD COLUMN category TEXT NOT NULL DEFAULT ''")
            }
        }

        // v3 menambahkan tabel threat_locations (fitur Peta Pola Ancaman).
        // Tanpa migration ini, device yang sudah punya DB v2 crash saat
        // upgrade ("migration from 2 to 3 was required but not found") —
        // setiap akses DB (recon, blacklist, sync) ikut gagal.
        private val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    """
                    CREATE TABLE IF NOT EXISTS `threat_locations` (
                        `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        `latitude` REAL NOT NULL,
                        `longitude` REAL NOT NULL,
                        `timestamp` INTEGER NOT NULL,
                        `crimeType` TEXT NOT NULL,
                        `severity` REAL NOT NULL,
                        `source` TEXT NOT NULL DEFAULT '',
                        `label` TEXT NOT NULL DEFAULT ''
                    )
                    """.trimIndent()
                )
            }
        }

        @Volatile
        private var INSTANCE: PhishingDatabase? = null

        fun getInstance(context: Context): PhishingDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    PhishingDatabase::class.java,
                    "phishing_database"
                )
                .addMigrations(MIGRATION_1_2, MIGRATION_2_3)
                .build()
                INSTANCE = instance
                instance
            }
        }
    }
}
