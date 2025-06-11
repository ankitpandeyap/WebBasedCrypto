package com.robspecs.Cryptography.dto;

import org.springframework.core.io.ByteArrayResource; // Import for ByteArrayResource

public class FileDownloadResponseDTO {
    private ByteArrayResource resource;
    private String fileName;
    private String contentType;

    /**
     * Constructs a FileDownloadResponseDTO.
     *
     * @param resource The actual file content as a ByteArrayResource.
     * @param fileName The original name of the file.
     * @param contentType The MIME type of the file.
     */
    public FileDownloadResponseDTO(ByteArrayResource resource, String fileName, String contentType) {
        this.resource = resource;
        this.fileName = fileName;
        this.contentType = contentType;
    }

    // --- Getters ---
    public ByteArrayResource getResource() {
        return resource;
    }

    public String getFileName() {
        return fileName;
    }

    public String getContentType() {
        return contentType;
    }

    // --- No setters needed for an immutable response DTO ---
}