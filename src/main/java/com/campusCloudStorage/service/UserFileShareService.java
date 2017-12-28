package com.campusCloudStorage.service;

import com.campusCloudStorage.dto.FriendFileShareItem;
import com.campusCloudStorage.enums.DeleteStateEnum;
import com.campusCloudStorage.enums.ShareStateEnum;


import java.util.List;

/**
 * 好友文件分享相关服务
 */
public interface UserFileShareService {
    /**
     * 根据指定用户与指定好友用户查询分享文件List
     * @param fromId
     * @param toId
     * @return 好友分享文件List
     */
    List<FriendFileShareItem> selectSharedFilesByUId(int fromId, int toId);

    /**
     * 新建好友分享文件记录
     * @param fromId 分享源用户Id
     * @param toId 分享目标用户Id
     * @param fId 文件Id
     * @param remark 分享备注
     * @return 分享状态
     */
    ShareStateEnum shareFileWithFriend(int fromId, int toId, int fId, String remark);

    /**
     * 取消指定好友分享文件
     * @param fromId 分享源用户Id
     * @param toId 分享目标用户Id
     * @param fId 文件Id
     * @return 删除状态
     */
    DeleteStateEnum deleteByPrimaryKey(int fromId, int toId, int fId);
}
