package com.alex193a.rootmypixel.domain.usecase

import android.net.Uri
import com.alex193a.rootmypixel.core.Result
import com.alex193a.rootmypixel.domain.model.TargetProfile
import com.alex193a.rootmypixel.domain.repository.PayloadError
import com.alex193a.rootmypixel.domain.repository.PayloadRepository

class ExtractBootImageUseCase(private val repository: PayloadRepository) {
    suspend operator fun invoke(
        uri: Uri,
        onProgress: (String) -> Unit = {},
    ): Result<TargetProfile, PayloadError> =
        repository.extractFromBootImage(uri, onProgress)
}
