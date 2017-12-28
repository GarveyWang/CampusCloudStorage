package com.campusCloudStorage.dao;

import com.campusCloudStorage.entity.FileHeader;

import java.util.List;

/**
 * 文件头相关Dao
 */
public interface FileHeaderDao {
    /**
     * 删除指定主键的记录
     * @param fId 主键
     * @return 删除的数目，1为成功，0为失败
     */
    int deleteByPrimaryKey(Integer fId);

    /**
     * 删除拥有指定父文件夹Id的文件夹记录
     * @param parentId 父文件夹Id
     * @return 删除的数目
     */
    int deleteByParentId(Integer parentId);

    /**
     * 插入一条完整记录（不允许非空无默认值的字段为null）
     * @param record 记录
     * @return 插入的数目，1为成功，0为失败
     */
    int insert(FileHeader record);

    /**
     * 查询指定主键的文件记录
     * @param fId 文件主键
     * @return 拥有指定主键的文件记录
     */
    FileHeader selectByPrimaryKey(Integer fId);

    /**
     * 查询拥有相同指定父目录的文件List
     * @param parentId 父目录
     * @return 文件List
     */
    List<FileHeader> selectByParentId(Integer parentId);

    /**
     * 更新指定主键的文件记录
     * @param record 记录
     * @return 更新的数目，1为成功，0为失败
     */
    int updateByPrimaryKey(FileHeader record);

    //int updateByPrimaryKeySelective(FileHeader record);
}