package com.campusCloudStorage.service;

import com.campusCloudStorage.dto.GroupFileShareItem;
import com.campusCloudStorage.enums.DeleteStateEnum;
import com.campusCloudStorage.enums.ShareStateEnum;

import java.util.List;

public interface GroupFileShareService {
    /**
     * 根据群组Id查询该群组的分享文件List
     * @param gId 群组Id
     * @return 群组分享文件List
     */
    List<GroupFileShareItem> getGroupSharedFilesByGId(int gId);

    /**
     * 插入群组分享文件
     * @param uId 分享者Id
     * @param gId 群组Id
     * @param fId 文件Id
     * @param remark 分享备注
     * @return 分享状态
     */
    ShareStateEnum insertGroupSharedFile(int uId, int gId, int fId, String remark);

    /**
     * 根据主键删除群组分享文件
     * @param uId 分享者Id
     * @param gId 群组Id
     * @param fId 文件Id
     * @return 删除状态
     */
    DeleteStateEnum deleteByPrimaryKey(int uId, int gId, int fId);

    /**
     * 根据群组Id和文件Id删除群组分享文件
     * @param gId 群组Id
     * @param fId 文件Id
     * @return 删除状态
     */
    DeleteStateEnum deleteByGIdAndFId(int gId, int fId);
}
