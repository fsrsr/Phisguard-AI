package com.phishguard.ai.data.db

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query

/**
 * Database URL Phishing.
 * Menyimpan URL yang diketahui sebagai phishing.
 */
@Entity(tableName = "phishing_urls")
data class PhishingUrl(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val url: String,
    val domain: String = "",
    val reason: String,
    val source: String = "local",   // "local", "server", "user_report"
    val confidence: Float = 1.0f,
    val isCommunityReported: Boolean = false,  // true = dari Firebase komunitas
    val addedAt: Long = System.currentTimeMillis()
)

@Dao
interface PhishingUrlDao {

    @Query("SELECT * FROM phishing_urls WHERE url = :url OR domain = :url LIMIT 1")
    fun findByUrl(url: String): PhishingUrl?

    @Query("SELECT * FROM phishing_urls WHERE domain = :domain LIMIT 1")
    fun findByDomain(domain: String): PhishingUrl?

    @Query("SELECT * FROM phishing_urls ORDER BY addedAt DESC")
    fun getAll(): List<PhishingUrl>

    @Query("SELECT COUNT(*) FROM phishing_urls")
    fun getCount(): Int

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insert(phishingUrl: PhishingUrl)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insertAll(urls: List<PhishingUrl>)

    @Query("DELETE FROM phishing_urls")
    fun deleteAll()
    
    @Query("DELETE FROM phishing_urls WHERE url = :url")
    fun deleteByUrl(url: String)
    
    @Query("SELECT * FROM phishing_urls WHERE source = :source")
    fun getBySource(source: String): List<PhishingUrl>

    @Query("DELETE FROM phishing_urls WHERE source = :source")
    fun deleteBySource(source: String)
}
