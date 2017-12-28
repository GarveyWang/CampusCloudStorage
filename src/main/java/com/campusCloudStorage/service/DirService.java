package com.campusCloudStorage.service;

import com.campusCloudStorage.entity.Dir;
import com.campusCloudStorage.entity.FileHeader;
import com.campusCloudStorage.enums.DeleteStateEnum;
import com.campusCloudStorage.enums.CreateStateEnum;
import com.campusCloudStorage.enums.UpdateStateEnum;

import java.util.List;

/**
 * 文件夹服务类
 */
public interface DirService {
    /**
     * 创建文件夹记录
     * @param dir 文件夹对象
     * @return 创建状态
     */
    CreateStateEnum createDir(Dir dir);

    /**
     * 更新文件夹记录
     * @param dir 更新后的文件夹对象
     * @return 更新状态
     */
    UpdateStateEnum updateDir(Dir dir);

    /**
     * 删除文件夹记录
     * @param dId 需要删除的文件夹主键
     * @return 删除状态
     */
    DeleteStateEnum deleteDirById(int dId);

    /**
     * 查询指定文件夹Id的文件夹，无子文件夹和子文件
     * @param dId 需要查询的文件夹Id
     * @return 指定Id的文件夹对象
     */
    Dir getDirById(int dId);

    /**
     * 获取带有子文件夹和子文件集合的文件夹对象
     * @param dId 文件夹Id
     * @return 文件夹对象
     */
    Dir getDirWithFirstChildrenById(int dId);

    /**
     * 通过父文件夹Id查询子文件夹List
     * @param dId 父文件夹Id
     * @return 子文件夹List
     */
    List<Dir> getFirstChildrenDirs(int dId);

    /**
     * 通过父文件夹Id查询该文件夹下的子文件List
     * @param dId 父文件夹Id
     * @return 子文件List
     */
    List<FileHeader> getFirstChildrenFileHeaders(int dId);

    /**
     * 通过父文件夹Id查询该文件夹下的所有文件夹List
     * @param dId 父文件夹Id
     * @return 该文件夹下所有子孙文件夹
     */
    Dir getDirWithAllChildren(int dId);

    /**
     * 查询指定文件夹的兄弟文件List
     * @param dir 指定文件夹对象
     * @return 兄弟文件List
     */
    List<Dir> getSiblingDirs(Dir dir);

    /**
     * 查询指定文件夹的路径文件夹
     * @param dir 指定文件夹
     * @return 文件夹路径List
     */
    List<Dir> getPathList(Dir dir);

}
