package com.campusCloudStorage.service.impl;


import com.campusCloudStorage.dao.FileHeaderDao;
import com.campusCloudStorage.dao.GroupFileShareDao;
import com.campusCloudStorage.dao.UserDao;
import com.campusCloudStorage.dto.GroupFileShareItem;
import com.campusCloudStorage.entity.FileHeader;
import com.campusCloudStorage.entity.GroupFileShare;
import com.campusCloudStorage.entity.GroupFileShareKey;
import com.campusCloudStorage.entity.User;
import com.campusCloudStorage.enums.DeleteStateEnum;
import com.campusCloudStorage.enums.ShareStateEnum;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.List;


@Service("groupFileShareService")
public class GroupFileShareServiceImpl implements com.campusCloudStorage.service.GroupFileShareService{
    @Resource
    private GroupFileShareDao groupFileShareDao;

    @Resource
    private FileHeaderDao fileHeaderDao;

    @Resource
    private UserDao userDao;


    @Override
    public List<GroupFileShareItem> getGroupSharedFilesByGId(int gId) {
        List<GroupFileShare> groupFileShareList=groupFileShareDao.selectByGId(gId);
        List<GroupFileShareItem> fileShareList=new ArrayList<GroupFileShareItem>();
        for (GroupFileShare groupFileShare: groupFileShareList) {
            GroupFileShareItem shareItem=new GroupFileShareItem();
            FileHeader fileHeader= fileHeaderDao.selectByPrimaryKey(groupFileShare.getfId());
            if(fileHeader!=null){
                User provider=userDao.selectByPrimaryKey(groupFileShare.getProviderId());
                shareItem.setFileHeader(fileHeader);
                shareItem.setGroupFileShare(groupFileShare);
                shareItem.setProvider(provider);
                fileShareList.add(shareItem);
            }
        }
        return fileShareList;
    }

    @Override
    public ShareStateEnum insertGroupSharedFile(int uId, int gId, int fId, String remark) {
       GroupFileShare groupFileShare=new GroupFileShare();
       groupFileShare.setProviderId(uId);
       groupFileShare.setgId(gId);
       groupFileShare.setfId(fId);
       groupFileShare.setRemark(remark);
       int insertCount=groupFileShareDao.insert(groupFileShare);
       if(insertCount==1){
           return ShareStateEnum.SUCCESS;
       }else {
           return ShareStateEnum.REPEAT;
       }
    }

    @Override
    public DeleteStateEnum deleteByPrimaryKey(int uId, int gId, int fId) {
        GroupFileShareKey groupFileShareKey = new GroupFileShareKey();
        groupFileShareKey.setProviderId(uId);
        groupFileShareKey.setgId(gId);
        groupFileShareKey.setfId(fId);
        int deleteCount = groupFileShareDao.deleteByPrimaryKey(groupFileShareKey);
        if(deleteCount==1){
            return DeleteStateEnum.SUCCESS;
        }
        return DeleteStateEnum.FAILED;
    }

    @Override
    public DeleteStateEnum deleteByGIdAndFId(int gId, int fId) {
        int deleteCount = groupFileShareDao.deleteByGIdAndFId(gId,fId);
        if(deleteCount==1){
            return DeleteStateEnum.SUCCESS;
        }
        return DeleteStateEnum.FAILED;
    }
}
