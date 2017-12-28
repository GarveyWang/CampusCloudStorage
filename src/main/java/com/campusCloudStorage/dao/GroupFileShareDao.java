package com.campusCloudStorage.dao;

import com.campusCloudStorage.entity.GroupFileShare;
import com.campusCloudStorage.entity.GroupFileShareKey;

import java.util.List;

/**
 * 群组文件分享相关Dao
 */
public interface GroupFileShareDao {
    /**
     * 删除指定主键的群组文件分享记录
     * @param key 主键
     * @return 删除的数目，1为成功，0为失败
     */
    int deleteByPrimaryKey(GroupFileShareKey key);

    /**
     * 删除指定群组中的指定成员的群组文件分享记录
     * @param gId 群组Id
     * @param providerId 成员Id
     * @return 删除的数目
     */
    int deleteByGIdAndProviderId(Integer gId, Integer providerId);

    /**
     * 删除指定群组中的指定文件分享记录
     * @param gId 群组Id
     * @param fId 文件Id
     * @return 删除的数目
     */
    int deleteByGIdAndFId(Integer gId, Integer fId);

    /**
     * 删除指定群组中的所有群组分享记录
     * @param gId 群组Id
     * @return 删除的数目
     */
    int deleteByGId(Integer gId);

    /**
     * 插入一条完整群组分享记录
     * @param record 记录
     * @return 插入的数目，1为成功，0为失败
     */
    int insert(GroupFileShare record);

    /**
     * 查询指定主键的群组分享记录
     * @param key 主键
     * @return 拥有指定主键的群组分享记录
     */
    GroupFileShare selectByPrimaryKey(GroupFileShareKey key);

    /**
     * 查询指定群组中的群组分享
     * @param gId
     * @return
     */
    List<GroupFileShare> selectByGId(Integer gId);


    //int updateByPrimaryKeySelective(GroupFileShare record);

    //int updateByPrimaryKey(GroupFileShare record);

    //int insertSelective(GroupFileShare record);
}