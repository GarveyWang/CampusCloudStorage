package com.campusCloudStorage.dao;

import com.campusCloudStorage.entity.UserFileShare;
import com.campusCloudStorage.entity.UserFileShareKey;

import java.util.List;

/**
 * 好友文件分享相关的Dao
 */
public interface UserFileShareDao {
    /**
     * 删除指定主键的好友文件分享记录
     * @param key 主键
     * @return 删除的数目，1为成功，0为失败
     */
    int deleteByPrimaryKey(UserFileShareKey key);

    /**
     * 删除指定文件Id的好友分享文件记录
     * @param fId 文件Id
     * @return 删除的数目
     */
    int deleteByFId(int fId);

    /**
     * 插入指定的好友文件共享记录
     * @param record 记录
     * @return 插入的数目，1为成功，0为失败
     */
    int insert(UserFileShare record);

    /**
     * 选择性插入指定的好友文件共享记录
     * @param record 记录
     * @return 插入的数目，1为成功，0为失败
     */
    int insertSelective(UserFileShare record);

    /**
     * 查询指定主键的好友文件共享记录
     * @param key 主键
     * @return 拥有指定主键的好友文件共享记录
     */
    UserFileShare selectByPrimaryKey(UserFileShareKey key);

    /**
     * 选择性更新指定主键的好友文件共享记录，仅更新非空字段
     * @param record 主键
     * @return 更新的数目，1为成功，0为失败
     */
    int updateByPrimaryKeySelective(UserFileShare record);

    /**
     * 更新指定主键的好友文件共享记录
     * @param record
     * @return
     */
    int updateByPrimaryKey(UserFileShare record);

    /**
     * 查询某一用户给另一用户的分享文件记录
     * @param fromId 本用户
     * @param toId 目标用户
     * @return 一用户给另一用户的分享文件记录List
     */
    List<UserFileShare> selectByUId(int fromId, int toId);
}