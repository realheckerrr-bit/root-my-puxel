package com.alex193a.rootmypixel.data.repository

import android.net.Uri
import android.util.Base64
import com.alex193a.rootmypixel.core.boot.BootImageReader
import com.alex193a.rootmypixel.core.kallsyms.KallsymsScanner
import com.alex193a.rootmypixel.core.kallsyms.SymbolResolver
import com.alex193a.rootmypixel.core.Result
import com.alex193a.rootmypixel.data.datasource.PayloadLocalDataSource
import com.alex193a.rootmypixel.data.model.toDomain
import com.alex193a.rootmypixel.domain.model.DeviceSnapshot
import com.alex193a.rootmypixel.domain.model.TargetProfile
import com.alex193a.rootmypixel.domain.model.VerifiedPayloads
import com.alex193a.rootmypixel.domain.repository.PayloadError
import com.alex193a.rootmypixel.domain.repository.PayloadRepository
import java.io.File

/**
 * Repository that reads everything from APK assets.
 * Profiles are loaded from assets/profiles.json, exploit .so and ksud
 * binaries are extracted from assets/ on demand.
 */
class PayloadRepositoryImpl(
    private val localDataSource: PayloadLocalDataSource,
    private val filesDir: File,
) : PayloadRepository {

    private var cachedProfiles: List<TargetProfile>? = null
    private val customProfiles = mutableMapOf<String, TargetProfile>()
    private val customConfigs = mutableMapOf<String, File>()

    init {
        loadCustomProfiles()
    }

    override suspend fun resolveTarget(
        snapshot: DeviceSnapshot,
    ): Result<TargetProfile, PayloadError> {
        return when (val result = loadCachedProfiles()) {
            is Result.Error -> result
            is Result.Success -> {
                val profiles = result.data + customProfiles.values

                val targetCodename = snapshot.device.trim()
                val targetKernelRel = snapshot.kernelRelease.trim()

                // /proc/version appends a Git revision to uname -r (for example,
                // "6.6.118-android15-8-g<sha>"). Profiles intentionally keep the
                // stable release prefix, but the build display is also part of the
                // payload identity: two builds can share a kernel release while
                // having different exploit offsets.
                val kernelMatches = profiles.filter { profile ->
                    targetCodename.isNotEmpty() &&
                        profile.codename.equals(targetCodename, ignoreCase = true) &&
                        (targetKernelRel == profile.kernelRelease ||
                            targetKernelRel.startsWith("${profile.kernelRelease}-"))
                }

                val buildMatches = kernelMatches.filter { profile ->
                    targetBuildMatches(profile.buildDisplay, snapshot.buildDisplay)
                }

                when {
                    buildMatches.size == 1 -> Result.Success(buildMatches.single())
                    kernelMatches.size == 1 && snapshot.buildDisplay.isBlank() ->
                        Result.Error(
                            PayloadError.UnsupportedError(
                                "Build display is unavailable; refusing to guess a payload for " +
                                    "${kernelMatches.single().profileId}",
                            ),
                        )
                    kernelMatches.size > 1 -> Result.Error(
                        PayloadError.UnsupportedError(
                            "Multiple payloads match $targetCodename / $targetKernelRel; " +
                                "exact build display required",
                        ),
                    )
                    kernelMatches.size == 1 -> Result.Error(
                        PayloadError.UnsupportedError(
                            "Build ${snapshot.buildDisplay.ifBlank { "<unknown>" }} is not supported " +
                                "for ${kernelMatches.single().profileId}",
                        ),
                    )
                    else -> Result.Error(
                        PayloadError.UnsupportedError(
                            "No profile for $targetCodename / $targetKernelRel"
                        )
                    )
                }
            }
        }
    }

    override suspend fun resolveTarget(
        profileId: String,
    ): Result<TargetProfile, PayloadError> {
        customProfiles[profileId]?.let { return Result.Success(it) }
        return when (val result = loadCachedProfiles()) {
            is Result.Error -> result
            is Result.Success -> {
                val profile = result.data.find { it.profileId == profileId }
                if (profile != null) {
                    Result.Success(profile)
                } else {
                    Result.Error(PayloadError.UnsupportedError("Profile $profileId not found"))
                }
            }
        }
    }

    override suspend fun extractPayloads(
        profile: TargetProfile,
        onProgress: (String) -> Unit,
    ): Result<VerifiedPayloads, PayloadError> {
        val payloadDir = File(filesDir, "payloads/${profile.profileId}")
        if (!payloadDir.isDirectory && !payloadDir.mkdirs()) {
            return Result.Error(PayloadError.ExtractionError("Unable to create payload directory"))
        }

        // Extract exploit .so from assets
        val exploitFile = File(payloadDir, "exploit.so")
        exploitFile.delete()
        val exploitResult = localDataSource.extractAsset(
            assetPath = profile.exploitAsset,
            destination = exploitFile,
            onProgress = onProgress,
        )
        if (exploitResult.isFailure) {
            return Result.Error(
                PayloadError.ExtractionError(
                    "Failed to extract exploit: ${exploitResult.exceptionOrNull()?.message}"
                )
            )
        }
        if (!exploitFile.setExecutable(true, true)) {
            exploitFile.delete()
            return Result.Error(PayloadError.ExtractionError("Unable to make exploit executable"))
        }

        // Dynamic profiles use the KMI-specific asset. Keep the legacy fallback
        // for older APKs and statically bundled payloads.
        val ksudAssetPath = "${PayloadLocalDataSource.KSUD_ASSET_PREFIX}ksud-${profile.kmi}"
        val ksudFile = File(payloadDir, "ksud")
        ksudFile.delete()
        var ksudResult = localDataSource.extractAsset(ksudAssetPath, ksudFile, onProgress)
        if (ksudResult.isFailure) {
            ksudResult = localDataSource.extractAsset(
                assetPath = "${PayloadLocalDataSource.KSUD_ASSET_PREFIX}ksud",
                destination = ksudFile,
                onProgress = onProgress,
            )
        }
        if (ksudResult.isFailure) {
            exploitFile.delete()
            return Result.Error(
                PayloadError.ExtractionError(
                    "Failed to extract ksud: ${ksudResult.exceptionOrNull()?.message}"
                )
            )
        }
        if (!ksudFile.setExecutable(true, true)) {
            exploitFile.delete()
            ksudFile.delete()
            return Result.Error(PayloadError.ExtractionError("Unable to make ksud executable"))
        }

        onProgress("Payloads ready")
        return Result.Success(
            VerifiedPayloads(
                exploit = exploitFile,
                kernelSu = ksudFile,
                kmi = profile.kmi,
                targetConfig = customConfigs[profile.profileId],
            ),
        )
    }

    override suspend fun loadTargets(): Result<List<TargetProfile>, PayloadError> {
        return when (val result = loadCachedProfiles()) {
            is Result.Error -> result
            is Result.Success -> Result.Success(result.data + customProfiles.values)
        }
    }

    override suspend fun extractFromBootImage(
        uri: Uri,
        onProgress: (String) -> Unit,
    ): Result<TargetProfile, PayloadError> = try {
        val kernel = BootImageReader(localDataSource.contentResolver).readKernel(uri, onProgress)
        onProgress("Analyzing kernel symbols…")
        val release = Regex("Linux version\\s+([^\\s]+)")
            .find(String(kernel, Charsets.ISO_8859_1))
            ?.groupValues
            ?.get(1)
            ?: throw IllegalArgumentException("Kernel release banner not found")
        val started = System.currentTimeMillis()
        val symbols = KallsymsScanner().resolve(kernel, SymbolResolver.requiredSymbols)
        val elapsed = System.currentTimeMillis() - started
        require(elapsed <= KALLSYMS_BUDGET_MS) {
            "Kernel symbol analysis exceeded time budget ($elapsed ms)"
        }
        val config = SymbolResolver.toConfig(release, symbols)
        val kmi = if (config.kernelFamily == 61) "android14-6.1" else "android15-6.6"
        val id = "custom-${release.replace(Regex("[^A-Za-z0-9._-]"), "_")}"
        val profile = TargetProfile(
            profileId = id,
            codename = "custom",
            kernelRelease = release,
            buildDisplay = id,
            exploitAsset = "exploits/cve-2026-43499-generic-${config.kernelFamily / 10}.${config.kernelFamily % 10}.so",
            kmi = kmi,
        )
        val customDir = File(filesDir, "custom_profiles").apply { mkdirs() }
        val configFile = File(customDir, "$id.bin").apply { writeBytes(config.toBinary()) }
        val metadata = """
            {"profileId":"$id","codename":"custom","kernelRelease":"$release",
             "buildDisplay":"$id","exploitAsset":"${profile.exploitAsset}",
             "kmi":"$kmi","config":"${Base64.encodeToString(config.toBinary(), Base64.NO_WRAP)}"}
        """.trimIndent()
        File(customDir, "$id.json").writeText(metadata)
        customProfiles[id] = profile
        customConfigs[id] = configFile
        cachedProfiles = null
        onProgress("Runtime target generated")
        Result.Success(profile)
    } catch (error: Throwable) {
        Result.Error(
            PayloadError.ExtractionError(
                error.message ?: "Failed to analyze boot image",
            ),
        )
    }

    private fun loadCustomProfiles() {
        val dir = File(filesDir, "custom_profiles")
        if (!dir.isDirectory) return
        dir.listFiles { file -> file.extension == "json" }?.forEach { file ->
            try {
                val raw = file.readText()
                fun value(key: String): String? =
                    Regex("\\\"$key\\\":\\\"([^\\\"]+)\\\"").find(raw)?.groupValues?.get(1)
                val id = value("profileId") ?: return@forEach
                val profile = TargetProfile(
                    profileId = id,
                    codename = value("codename") ?: "custom",
                    kernelRelease = value("kernelRelease") ?: return@forEach,
                    buildDisplay = value("buildDisplay") ?: id,
                    exploitAsset = value("exploitAsset") ?: "exploits/cve-2026-43499-generic-6.1.so",
                    kmi = value("kmi") ?: "android14-6.1",
                )
                customProfiles[id] = profile
                value("config")?.let { encoded ->
                    val configFile = File(dir, "$id.bin")
                    if (!configFile.exists()) configFile.writeBytes(Base64.decode(encoded, Base64.NO_WRAP))
                    customConfigs[id] = configFile
                }
            } catch (_: Throwable) {
                // Ignore a partially written custom profile and keep bundled targets usable.
            }
        }
    }

    private fun loadCachedProfiles(): Result<List<TargetProfile>, PayloadError> {
        cachedProfiles?.let { return Result.Success(it) }

        return localDataSource.loadProfiles().fold(
            onSuccess = { dtos ->
                val profiles = dtos.map { it.toDomain() }
                cachedProfiles = profiles
                Result.Success(profiles)
            },
            onFailure = { throwable ->
                Result.Error(
                    PayloadError.ExtractionError(
                        throwable.message ?: "Failed to load profiles.json"
                    )
                )
            }
        )
    }

    private fun targetBuildMatches(profileBuild: String, targetBuild: String): Boolean =
        profileBuild.isNotBlank() && targetBuild.isNotBlank() &&
            profileBuild.trim().equals(targetBuild.trim(), ignoreCase = true)

    companion object {
        private const val KALLSYMS_BUDGET_MS = 30_000L
    }
}
