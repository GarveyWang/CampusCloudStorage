package com.campusCloudStorage.service;

import com.campusCloudStorage.entity.User;
import com.campusCloudStorage.entity.UserFriend;
import com.campusCloudStorage.enums.DeleteStateEnum;
import com.campusCloudStorage.enums.FriendRequestStateEnum;

import java.util.List;

public interface UserFriendService {
    /**
     * 查询指定用户已被同意的好友List
     * @param uId 用户Id
     * @return 已被同意的好友List
     */
    List<User> selectPermittedFriendsByUId(int uId);

    /**
     * 查询指定用户未被处理的好友请求List
     * @param uId 用户Id
     * @return 未被处理的好友请求List
     */
    List<User> selectFriendRequestByUId(int uId);

    /**
     * 发送好友请求
     * @param fromId 发送源用户Id
     * @param toId 发送目标用户Id
     * @return 好友请求发送状态
     */
    FriendRequestStateEnum sendFriendRequest(int fromId, int toId);

    /**
     * 同意好友请求
     * @param uId 发送目标用户Id
     * @param friendId 发送源用户Id
     * @return 同意好友请求状态
     */
    FriendRequestStateEnum permitFriendRequest(int uId, int friendId);

    /**
     * 删除好友
     * @param uId 发送目标用户Id
     * @param friendId 发送源用户Id
     * @return 删除好友状态
     */
    FriendRequestStateEnum deleteFriend(int uId, int friendId);
}
