package com.campusCloudStorage.dao;

import com.campusCloudStorage.entity.UserFriend;
import com.campusCloudStorage.entity.UserFriendKey;

import java.util.List;

/**
 * 好友相关的Dao
 */
public interface UserFriendDao {
    /**
     * 删除指定主键的好友记录
     * @param key 主键
     * @return 删除的数目，1为成功，0为失败
     */
    int deleteByPrimaryKey(UserFriendKey key);

    /**
     * 插入好友记录
     * @param record 记录
     * @return 插入的数目，1为成功，0为失败
     */
    int insert(UserFriend record);

    /**
     * 选择性插入好友记录
     * @param record 记录
     * @return 插入的数目，1为成功，0为失败
     */
    int insertSelective(UserFriend record);

    /**
     * 查询指定主键的好友记录
     * @param key 主键
     * @return 拥有指定主键的好友记录
     */
    UserFriend selectByPrimaryKey(UserFriendKey key);

    /**
     * 根据主键选择性更新好友记录的非空字段
     * @param record 记录
     * @return 更新的数目，1为成功，0为失败
     */
    int updateByPrimaryKeySelective(UserFriend record);

    /**
     * 根据主键更新所有的好友记录字段
     * @param record 记录
     * @return 更新的数目，1为成功，0为失败
     */
    int updateByPrimaryKey(UserFriend record);

    /**
     * 查询未同意的好友请求(自己发送给别人的)
     * @param fromId
     * @return
     */
    List<UserFriend> selectUnpermittedFriends(int fromId);

    /**
     * 查询未被同意的好友请求(别人发送给自己的)
     * @param toId
     * @return
     */
    List<UserFriend> selectFriendRequests(int toId);

    /**
     * 根据指定用户Id查询好友
     * @param uId 用户Id
     * @return 指定用户Id的好友List
     */
    List<UserFriend> selectFriends(int uId);
}