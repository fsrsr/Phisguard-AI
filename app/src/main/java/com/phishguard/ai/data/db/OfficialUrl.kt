package com.phishguard.ai.data.db

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query

/**
 * Database Domain Resmi (Whitelist).
 * Menyimpan domain yang terverifikasi sebagai resmi/aman.
 */
@Entity(tableName = "official_urls")
data class OfficialUrl(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val domain: String,
    val organization: String,   // e.g., "Bank BCA", "Bank BRI"
    val category: String,       // "banking", "government", "social", etc.
    val addedAt: Long = System.currentTimeMillis()
)

@Dao
interface OfficialUrlDao {

    @Query("SELECT * FROM official_urls WHERE domain = :domain LIMIT 1")
    fun findByDomain(domain: String): OfficialUrl?

    @Query("SELECT * FROM official_urls ORDER BY organization ASC")
    fun getAll(): List<OfficialUrl>

    @Query("SELECT COUNT(*) FROM official_urls")
    fun getCount(): Int

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insert(url: OfficialUrl)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insertAll(urls: List<OfficialUrl>)

    @Query("SELECT domain FROM official_urls")
    fun getAllDomains(): List<String>

    @Query("DELETE FROM official_urls")
    fun deleteAll()
}
