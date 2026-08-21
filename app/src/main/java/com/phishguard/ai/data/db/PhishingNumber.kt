package com.phishguard.ai.data.db

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query

/**
 * Database Nomor Telepon Penipu.
 * Menyimpan nomor yang diketahui sebagai sumber penipuan.
 */
@Entity(tableName = "phishing_numbers")
data class PhishingNumber(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val number: String,
    val reason: String,
    val source: String,         // "local", "server", "user_report"
    val confidence: Float = 1.0f,
    val addedAt: Long = System.currentTimeMillis()
)

@Dao
interface PhishingNumberDao {

    @Query("SELECT * FROM phishing_numbers WHERE number = :number LIMIT 1")
    fun findByNumber(number: String): PhishingNumber?

    @Query("SELECT * FROM phishing_numbers ORDER BY addedAt DESC")
    fun getAll(): List<PhishingNumber>

    @Query("SELECT COUNT(*) FROM phishing_numbers")
    fun getCount(): Int

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insert(number: PhishingNumber)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insertAll(numbers: List<PhishingNumber>)

    @Query("DELETE FROM phishing_numbers")
    fun deleteAll()
}
