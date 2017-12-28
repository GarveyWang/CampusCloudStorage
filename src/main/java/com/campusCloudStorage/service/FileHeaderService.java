package com.campusCloudStorage.service;


import com.campusCloudStorage.entity.FileHeader;
import com.campusCloudStorage.enums.CreateStateEnum;
import com.campusCloudStorage.enums.DeleteStateEnum;
import com.campusCloudStorage.enums.UpdateStateEnum;

public interface FileHeaderService {
    /**
     * 创建文件
     * @param fileHeader 文件
     * @return 创建状态
     */
    CreateStateEnum createFileHeader(FileHeader fileHeader);

    /**
     * 根据文件Id删除文件
     * @param fId 文件Id
     * @return 删除状态
     */
    DeleteStateEnum deleteFileHeader(int fId);

    /**
     * 根据文件Id查询相应文件
     * @param fId 文件id
     * @return 文件对象
     */
    FileHeader getFileHeaderById(int fId);

    /**
     * 更新文件
     * @param fileHeader 更新后的文件
     * @return 更新状态
     */
    UpdateStateEnum updateFileHeader(FileHeader fileHeader);
}
